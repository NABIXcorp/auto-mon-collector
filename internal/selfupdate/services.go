package selfupdate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/envfile"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
	"github.com/NABIXcorp/auto-mon-collector/internal/lockfile"
)

// The control plane's service switches (v0.33.0), root's half. The request is the signed document (verified again
// in loadRequest); the host owner's switch is answers.yaml agent.services_edit.allow and a kind locked there is never
// switched; the set is checked again (generate.CheckServicesSet: root does not trust the agent). answers.yaml is
// never edited: the set is its own file (generate.ServicesFile), merged over the answers by the generator (answers
// win). Before anything changes, each kind this set switches on must answer on 127.0.0.1 (nginx: the stub_status
// page; Redis: PING, or a password in the secrets). Then `monitoring-agent update` with the smoke run and automatic
// rollback; a failed update puts the previous file back.
//
//	verify -> switch -> kinds / locked -> service answers -> lock -> record -> write the set -> update --no-fetch
//	-> agent/services-result.json

// servicesJob: the request carries a set root has not handled, and no new update, overlay set or allowlist overlay
// (one root job per document: those go first).
func servicesJob(r request) bool {
	s := r.doc.Services
	if s == nil || s.Revision <= r.last.ServicesRevision {
		return false
	}
	return (r.doc.Update == nil || r.doc.Update.ID == r.last.ID) && !siteJob(r) && !allowJob(r)
}

func (o *Options) runServices(ctx context.Context, r request) (res agent.ServicesResult) {
	sv := r.doc.Services
	res = agent.ServicesResult{Revision: sv.Revision, DocRevision: r.doc.Revision}
	defer func() {
		res.At = o.Now().Unix()
		if len(res.Detail) > 1000 {
			res.Detail = res.Detail[:1000]
		}
		fmt.Fprintf(o.Out, "self-update: services %d: %s: %s\n", res.Revision, res.Result, res.Detail)
		if err := writeRoot(filepath.Join(o.Prefix, filepath.FromSlash(agent.ServicesResultFile)), marshal(res), 0o644); err != nil {
			fmt.Fprintf(o.Out, "self-update: write %s: %v\n", agent.ServicesResultFile, err)
		}
	}()
	set := func(result, format string, args ...any) agent.ServicesResult {
		res.Result, res.Detail = result, fmt.Sprintf(format, args...)
		return res
	}
	if err := generate.CheckServicesSet(sv.Set, r.answers.Agent.ServicesEdit, r.answers.Services); err != nil {
		return set("refused", "%v", err)
	}
	norm := sv.Set.Normalized()
	// the kinds this set switches on (one on in the answers anyway is not checked: nothing changes for it)
	for _, k := range norm.Kinds() {
		a := r.answers.Services[k]
		if !norm[k].On || (a.Enabled != nil && *a.Enabled) {
			continue
		}
		if err := o.checkService(ctx, k, norm[k]); err != nil {
			return set("refused", "nothing changed: %v", err)
		}
	}
	var data []byte // nil = remove the set
	if len(norm) > 0 {
		var err error
		if data, err = generate.MarshalServicesOverlay(generate.ServicesOverlay{Revision: sv.Revision, Set: norm}); err != nil {
			return set("refused", "%v", err)
		}
	}
	lk, err := lockfile.Acquire(o.Prefix)
	if err != nil {
		return set("refused", "%v", err)
	}
	defer lk.Release()
	rec := r.last
	rec.Revision, rec.ServicesRevision, rec.At = r.doc.Revision, sv.Revision, o.Now().Unix()
	if err := writeRoot(filepath.Join(o.Prefix, RecordFile), marshal(rec), 0o644); err != nil {
		return set("failed", "nothing changed: write %s: %v", RecordFile, err)
	}
	p := filepath.Join(o.Prefix, filepath.FromSlash(generate.ServicesFile))
	prev, err := os.ReadFile(p)
	had := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return set("failed", "nothing changed: %v", err)
	}
	if err := putOverlay(p, data); err != nil {
		if rerr := putOverlay(p, keep(had, prev)); rerr != nil {
			return set("failed", "write %s: %v; RESTORING the previous one FAILED: %v", generate.ServicesFile, err, rerr)
		}
		return set("failed", "nothing changed: write %s: %v", generate.ServicesFile, err)
	}
	what := "written (" + norm.String() + ")"
	if data == nil {
		what = "removed (empty set)"
	}
	fmt.Fprintf(o.Out, "self-update: services %d accepted: %s %s; running `update`\n", sv.Revision, generate.ServicesFile, what)
	binPath := filepath.Join(o.Prefix, "bin", "monitoring-agent")
	// --no-fetch: the set changes the configuration only; the installed collector and prober stay
	out, err := o.Run(lk.File(), binPath, "update", "--prefix", o.Prefix, "--no-fetch")
	o.Out.Write(out)
	if err == nil {
		return set("applied", "%s", lastLine(string(out)))
	}
	// the engine has put its own files back (or changed nothing): the previous set goes back too
	if rerr := putOverlay(p, keep(had, prev)); rerr != nil {
		return set("failed", "update failed (%v): %s; RESTORING the previous %s FAILED: %v", err, lastLine(string(out)), generate.ServicesFile, rerr)
	}
	if strings.Contains(string(out), "ROLLED BACK") {
		return set("rolled_back", "the new configuration did not start, the previous services and configuration run again: %s", lastLine(string(out)))
	}
	return set("failed", "nothing changed (%v): %s", err, lastLine(string(out)))
}

// checkService: does the kind answer on 127.0.0.1 where the set says? (Options.CheckService in tests)
func (o *Options) checkService(ctx context.Context, kind string, sw generate.ServiceSwitch) error {
	if o.CheckService != nil {
		return o.CheckService(ctx, kind, sw)
	}
	switch kind {
	case "nginx":
		return CheckNginx(ctx, "127.0.0.1:"+strconv.Itoa(sw.Port), sw.StatusPath)
	case "redis":
		return CheckRedis(ctx, "127.0.0.1:"+strconv.Itoa(sw.Port), func() bool { return o.hasSecret("REDIS_PASSWORD") })
	}
	return fmt.Errorf("no check for %s", kind)
}

// CheckNginx: GET the stub_status page at addr (2 s, no redirects); it must answer 200 with "Active connections:".
func CheckNginx(ctx context.Context, addr, path string) error {
	u := "http://" + addr + path
	fail := fmt.Errorf("nginx stub_status not answering at %s: add the location (see the console steps)", u)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fail
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		return fail
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), "Active connections:") {
		return fail
	}
	return nil
}

// CheckRedis: PING at addr (2 s). +PONG = fine; NOAUTH = fine only with a password in the secrets (the smoke run
// then shows whether it is the right one).
func CheckRedis(ctx context.Context, addr string, hasPassword func() bool) error {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("Redis not answering at %s: %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return fmt.Errorf("Redis not answering at %s: %v", addr, err)
	}
	line, rerr := bufio.NewReader(io.LimitReader(conn, 512)).ReadString('\n')
	line = strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(line, "+PONG"):
		return nil
	case strings.Contains(line, "NOAUTH") || strings.Contains(strings.ToLower(line), "authentication required"):
		if hasPassword() {
			return nil
		}
		return errors.New("Redis needs a password: put it in Secrets (REDIS_PASSWORD)")
	case rerr != nil && line == "":
		return fmt.Errorf("Redis not answering at %s: %v", addr, rerr)
	}
	return fmt.Errorf("not a Redis answer at %s: %.40q", addr, line)
}

// hasSecret: is key set (non-empty) in secrets/collector.env? Only its presence is read; the value is never used.
func (o *Options) hasSecret(key string) bool {
	b, err := os.ReadFile(filepath.Join(o.Prefix, "secrets", "collector.env"))
	if err != nil {
		return false
	}
	m, err := envfile.Parse(b)
	return err == nil && m[key] != ""
}
