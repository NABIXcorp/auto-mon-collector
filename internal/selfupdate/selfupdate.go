// Package selfupdate is `monitoring-agent self-update` (v0.16.0): root's half of a remote update requested through
// the agent
// (docs/design.md, section 17). Root does not trust the agent (user monitoring-agent): the ONLY input is the signed
// document the agent saved, and it is verified again here with the control-plane key pinned in the root-owned
// answers.yaml. The host owner's policy comes from answers.yaml agent.update only. The release is downloaded from
// the one repository compiled in below and must carry a valid signature of the release key embedded in this binary
// (keys/release.pub, the same check get.sh does); nothing of the URL, key or commands comes from the request.
//
//	verify the request -> policy (allow, downgrade, window) -> lock -> download SHA256SUMS + .sig + asset
//	-> verify -> keep bin/monitoring-agent.before-<old> -> install bin/monitoring-agent
//	-> new `version` -> new `update`
//	-> result (<prefix>/agent/update-result.json); on a failed version check or update the old binary goes back.
package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
	"github.com/NABIXcorp/auto-mon-collector/internal/lockfile"
	"github.com/NABIXcorp/auto-mon-collector/internal/version"
	"github.com/NABIXcorp/auto-mon-collector/keys"
)

// releaseBase: where a release comes from: <base><version>/<asset>. v0.24.0: the root-owned answers may name a
// mirror (release_mirror) that is tried first; never anything from the request. The embedded key checks the bytes
// from either place, and the new binary must report the requested version.
const releaseBase = "https://github.com/NABIXcorp/auto-mon-collector/releases/download/"

// replaced in tests only (an httptest server, a throwaway key, a small limit)
var (
	baseURL          = releaseBase
	releaseKey       = keys.ReleasePub
	maxBinary  int64 = 128 << 20 // a release binary is ~10 MB
)

const (
	maxSums    = 64 << 10
	maxSig     = 1 << 10 // a DER P-256 signature is at most 72 bytes
	maxRequest = 256 << 10
	// RecordFile (below the prefix, root 644): the last request root handled (id + revision): a replayed or
	// repeated request is refused even if the agent's own state was changed.
	RecordFile = "self-update.json"
	agentUnit  = "monitoring-agent.service"
)

// Runner runs a program and returns its combined output. lock != nil: pass it to the child as fd 3 (lockfile.EnvFD).
type Runner func(lock *os.File, name string, args ...string) ([]byte, error)

// Options of one self-update.
type Options struct {
	Prefix  string // default /opt/monitoring
	Request string // default <prefix>/agent/update-request.json
	Host    string // "" = the name the agent uses: answers host_name, else os.Hostname() (agent.HostName)
	Running string // the running monitoring-agent's version (version.Version)
	Arch    string // default runtime.GOARCH
	Now     func() time.Time
	HTTP    *http.Client
	Run     Runner
	Out     io.Writer
	RootUID int // uid that must own answers.yaml: 0 = root (tests use their own uid)

	mirror string // answers release_mirror (set by loadRequest)
}

// Run does one self-update and returns the result it also wrote to <prefix>/agent/update-result.json.
func Run(ctx context.Context, o Options) (res agent.UpdateResult) {
	o.defaults()
	res.From = o.Running
	changed := false // bin/monitoring-agent was replaced: the agent is restarted at the end (it then runs the new binary)
	keepResult := false
	defer func() {
		res.At = o.Now().Unix()
		if len(res.Detail) > 1000 {
			res.Detail = res.Detail[:1000]
		}
		fmt.Fprintf(o.Out, "self-update: %s: %s\n", res.Result, res.Detail)
		// no verified id (nothing to report it under) or a request handled before: the result file keeps the
		// earlier result, which the agent may not have reported yet
		if res.ID == "" || keepResult {
			return
		}
		if err := writeRoot(filepath.Join(o.Prefix, filepath.FromSlash(agent.UpdateResultFile)), marshal(res), 0o644); err != nil {
			fmt.Fprintf(o.Out, "self-update: write %s: %v\n", agent.UpdateResultFile, err)
		}
		if changed {
			if out, err := o.Run(nil, "systemctl", "try-restart", agentUnit); err != nil {
				fmt.Fprintf(o.Out, "self-update: restart %s: %v %s\n", agentUnit, err, lastLine(string(out)))
			}
		}
	}()
	set := func(result, format string, a ...any) agent.UpdateResult {
		res.Result, res.Detail = result, fmt.Sprintf(format, a...)
		return res
	}
	// v0.23.0: the same request file may carry the control plane's overlay set instead (site.go)
	if req, err := o.loadRequest(); err == nil && siteJob(req) {
		sr := o.runSite(ctx, req)
		return agent.UpdateResult{Result: sr.Result, Detail: sr.Detail, At: sr.At}
	}
	doc, pol, last, err := o.verifyRequest(&res)
	if errors.Is(err, errHandled) {
		keepResult = true
	}
	if err != nil {
		return set("refused", "%v", err)
	}
	target := doc.Update.Version
	if err := pol.Check(o.Running, target); err != nil {
		return set("refused", "%v", err)
	}
	if err := pol.InWindow(o.Now()); err != nil {
		return set("refused", "%v", err)
	}
	// no `monitoring-agent apply` / `update` at the same time (the unit itself never runs twice at once: oneshot)
	lk, err := lockfile.Acquire(o.Prefix)
	if err != nil {
		return set("refused", "%v", err)
	}
	defer lk.Release()
	// from here on the request counts as handled: it never runs a second time
	rec := record{ID: res.ID, Revision: doc.Revision, SiteRevision: last.SiteRevision, At: o.Now().Unix()}
	if err := writeRoot(filepath.Join(o.Prefix, RecordFile), marshal(rec), 0o644); err != nil {
		return set("failed", "nothing changed: write %s: %v", RecordFile, err)
	}
	fmt.Fprintf(o.Out, "self-update: request %s accepted: %s -> %s\n", res.ID, o.Running, target)

	asset := "monitoring-agent-linux-" + o.Arch // v0.20.0 and later
	bin, err := o.download(ctx, target, asset)
	if err != nil {
		return set("failed", "nothing changed: %v", err)
	}
	fmt.Fprintf(o.Out, "self-update: %s %s: signature and sha256 verified\n", asset, target)

	binPath := filepath.Join(o.Prefix, "bin", "monitoring-agent")
	old, err := os.ReadFile(binPath)
	if err != nil {
		return set("failed", "nothing changed: %v", err)
	}
	keep := binPath + ".before-" + fileVersion(o.Running)
	if err := writeRoot(keep, old, 0o755); err != nil {
		return set("failed", "nothing changed: keep the old binary: %v", err)
	}
	if err := writeRoot(binPath, bin, 0o755); err != nil {
		return set("failed", "nothing changed: install: %v", err)
	}
	changed = true
	restore := func(why string) agent.UpdateResult {
		if err := writeRoot(binPath, old, 0o755); err != nil {
			return set("failed", "%s; RESTORING the previous binary FAILED (%v): it is in %s", why, err, keep)
		}
		return set("rolled_back", "%s; previous version %s restored", why, o.Running)
	}
	out, err := o.Run(nil, binPath, "version")
	if got := strings.TrimSpace(string(out)); err != nil || !strings.HasPrefix(got, "auto-mon-collector "+target+" ") {
		return restore(fmt.Sprintf("the new binary reports %q, want %s", lastLine(got), target))
	}
	fmt.Fprintf(o.Out, "self-update: bin/%s is %s (previous kept as %s); running `update`\n", filepath.Base(binPath), target, filepath.Base(keep))
	out, err = o.Run(lk.File(), binPath, "update", "--prefix", o.Prefix)
	o.Out.Write(out)
	if err != nil {
		return restore(fmt.Sprintf("update failed (%v): %s", err, lastLine(string(out))))
	}
	return set("ok", "%s installed, `update` done", target)
}

func (o *Options) defaults() {
	if o.Prefix == "" {
		o.Prefix = "/opt/monitoring"
	}
	if o.Request == "" {
		o.Request = filepath.Join(o.Prefix, filepath.FromSlash(agent.UpdateRequestFile))
	}
	// v0.24.1: the agent enrols and signs as answers host_name when it is set (on a host whose OS name differs from it,
	// every request was refused "document is for host ..."); the same rule here
	if o.Host == "" {
		o.Host = agent.HostName(o.Prefix)
	}
	if o.Host == "" {
		o.Host, _ = os.Hostname()
	}
	if o.Arch == "" {
		o.Arch = runtime.GOARCH
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 10 * time.Minute, CheckRedirect: noDowngrade}
	}
	if o.Run == nil {
		o.Run = execRun
	}
	if o.Out == nil {
		o.Out = os.Stdout
	}
}

// noDowngrade: GitHub answers a release download with a redirect to its storage; follow at most 5, never from
// https to http (the signature protects the bytes anyway).
func noDowngrade(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("redirect from https to " + req.URL.Scheme + " refused")
	}
	return nil
}

func execRun(lock *os.File, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...) // no context: a running `monitoring-agent update` is never killed half-way by us
	if lock != nil {
		cmd.ExtraFiles = []*os.File{lock} // fd 3
		cmd.Env = append(os.Environ(), lockfile.EnvFD+"=3")
	}
	return cmd.CombinedOutput()
}

var errHandled = errors.New("handled already")

type record struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	// v0.23.0: the last overlay set root handled
	SiteRevision int64 `json:"site_revision,omitempty"`
	At           int64 `json:"at"`
}

// request is a verified request: the signed document, the root-owned answers and root's record of the last one.
type request struct {
	doc     agent.Doc
	answers generate.Answers
	last    record
}

// loadRequest: the root-owned answers (agent section, pinned key), then the request file: signature, host,
// revision (above the last one root handled), expiry.
func (o *Options) loadRequest() (request, error) {
	var r request
	ap := filepath.Join(o.Prefix, "answers.yaml")
	if err := rootOwned(ap, o.RootUID); err != nil {
		return r, err
	}
	a, err := generate.LoadAnswers(ap)
	if err != nil {
		return r, err
	}
	if a.Agent == nil {
		return r, errors.New("answers.yaml has no agent section")
	}
	r.answers = a
	if a.ReleaseMirror != "" && generate.ValidMirror(a.ReleaseMirror) == nil {
		o.mirror = a.ReleaseMirror
	}
	cpKey, err := generate.ParseKey(a.Agent.ControlPlaneKey)
	if err != nil {
		return r, err
	}
	raw, err := readRequest(o.Request)
	if err != nil {
		return r, fmt.Errorf("request: %w", err)
	}
	if b, err := os.ReadFile(filepath.Join(o.Prefix, RecordFile)); err == nil {
		if err := unmarshal(b, &r.last); err != nil {
			return r, fmt.Errorf("%s: %v (remove it to reset)", RecordFile, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return r, err
	}
	r.doc, err = agent.VerifySigned(raw, cpKey, o.Host, r.last.Revision, o.Now())
	if err != nil {
		return r, fmt.Errorf("request: %v", err)
	}
	return r, nil
}

// verifyRequest: loadRequest, then an update with a valid id and version, not handled before.
func (o *Options) verifyRequest(res *agent.UpdateResult) (agent.Doc, generate.AgentUpdate, record, error) {
	var none generate.AgentUpdate
	req, err := o.loadRequest()
	if err != nil {
		return req.doc, none, req.last, err
	}
	doc, last := req.doc, req.last
	u := doc.Update
	if u == nil {
		return doc, none, last, errors.New("request: the signed document asks for no update (and no new overlay set)")
	}
	if !agent.ValidUpdateID(u.ID) {
		return doc, none, last, errors.New("request: update id malformed")
	}
	res.ID, res.Revision = u.ID, doc.Revision
	if _, err := version.Parse(u.Version); err != nil {
		return doc, none, last, fmt.Errorf("request: %v", err)
	}
	res.To = u.Version
	if u.ID == last.ID {
		return doc, none, last, fmt.Errorf("request %s: %w", u.ID, errHandled)
	}
	return doc, req.answers.Agent.Update, last, nil
}

// download: from the mirror (answers release_mirror) when there is one, else / on any error from GitHub.
func (o *Options) download(ctx context.Context, v, asset string) ([]byte, error) {
	if o.mirror != "" {
		b, err := o.downloadFrom(ctx, o.mirror, v, asset)
		if err == nil {
			return b, nil
		}
		fmt.Fprintf(o.Out, "self-update: release mirror: %v; using GitHub\n", err)
	}
	return o.downloadFrom(ctx, baseURL, v, asset)
}

// downloadFrom fetches SHA256SUMS, its signature and asset of release v, and verifies them with the embedded key.
func (o *Options) downloadFrom(ctx context.Context, root, v, asset string) ([]byte, error) {
	if _, err := version.Parse(v); err != nil { // checked before; the URL is built from it
		return nil, err
	}
	if o.Arch != "amd64" && o.Arch != "arm64" {
		return nil, fmt.Errorf("no release asset for %s", o.Arch)
	}
	key, err := ParseReleaseKey(releaseKey)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	base := root + v + "/"
	sums, err := o.get(ctx, base, "SHA256SUMS", maxSums)
	if err != nil {
		return nil, err
	}
	sig, err := o.get(ctx, base, "SHA256SUMS.sig", maxSig)
	if err != nil {
		return nil, err
	}
	if err := VerifySums(key, sums, sig); err != nil { // before the large download
		return nil, err
	}
	bin, err := o.get(ctx, base, asset, maxBinary)
	if err != nil {
		return nil, err
	}
	if err := VerifyAsset(key, sums, sig, asset, bin); err != nil {
		return nil, err
	}
	return bin, nil
}

func (o *Options) get(ctx context.Context, base, name string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+name, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "monitoring-agent-self-update")
	resp, err := o.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", name, resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("download %s: too large (%d bytes, limit %d)", name, resp.ContentLength, limit)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", name, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("download %s: too large (limit %d bytes)", name, limit)
	}
	return b, nil
}

// fileVersion: the running version for the file name bin/monitoring-agent.before-<v> (a non-release build = "unknown").
func fileVersion(v string) string {
	if _, err := version.Parse(v); err != nil {
		return "unknown"
	}
	return v
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
