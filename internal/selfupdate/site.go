package selfupdate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
	"github.com/NABIXcorp/auto-mon-collector/internal/lockfile"
)

// Overlays from the control plane (v0.23.0), root's half. The request is the signed document (verified again in
// loadRequest); the host owner's switch is answers.yaml agent.site.allow; the set is checked against the catalog
// again (generate.CheckSite: root does not trust the agent). Then the new site.d = the host owner's own files
// (without generate.SitePrefix) + the control plane's set, and `monitoring-agent update --site-dir <that>` does
// plan (validate + smoke run) -> apply -> start -> automatic rollback, as for every other change.
//
//	verify -> switch -> catalog -> lock -> record -> stage site.d -> update --site-dir -> agent/site-result.json

// siteJob: the request carries an overlay set root has not handled, and no new update (an update goes first).
func siteJob(r request) bool {
	s := r.doc.Site
	if s == nil || s.Revision <= r.last.SiteRevision {
		return false
	}
	return r.doc.Update == nil || r.doc.Update.ID == r.last.ID
}

func (o *Options) runSite(ctx context.Context, r request) (res agent.SiteResult) {
	s := r.doc.Site
	res = agent.SiteResult{Revision: s.Revision, DocRevision: r.doc.Revision}
	defer func() {
		res.At = o.Now().Unix()
		if len(res.Detail) > 1000 {
			res.Detail = res.Detail[:1000]
		}
		fmt.Fprintf(o.Out, "self-update: overlays %d: %s: %s\n", res.Revision, res.Result, res.Detail)
		if err := writeRoot(filepath.Join(o.Prefix, filepath.FromSlash(agent.SiteResultFile)), marshal(res), 0o644); err != nil {
			fmt.Fprintf(o.Out, "self-update: write %s: %v\n", agent.SiteResultFile, err)
		}
	}()
	set := func(result, format string, a ...any) agent.SiteResult {
		res.Result, res.Detail = result, fmt.Sprintf(format, a...)
		return res
	}
	if !r.answers.Agent.Site.Allow {
		return set("refused", "overlays from the control plane are off on this host (answers.yaml agent.site.allow)")
	}
	if err := generate.CheckSite(s.Files); err != nil {
		return set("refused", "%v", err)
	}
	lk, err := lockfile.Acquire(o.Prefix)
	if err != nil {
		return set("refused", "%v", err)
	}
	defer lk.Release()
	rec := record{ID: r.last.ID, Revision: r.doc.Revision, SiteRevision: s.Revision, At: o.Now().Unix()}
	if err := writeRoot(filepath.Join(o.Prefix, RecordFile), marshal(rec), 0o644); err != nil {
		return set("failed", "nothing changed: write %s: %v", RecordFile, err)
	}
	stage, err := os.MkdirTemp(o.Prefix, ".site-stage-") // root 700, removed below
	if err != nil {
		return set("failed", "nothing changed: %v", err)
	}
	defer os.RemoveAll(stage)
	own, err := o.stageSite(stage, s.Files)
	if err != nil {
		return set("failed", "nothing changed: %v", err)
	}
	fmt.Fprintf(o.Out, "self-update: overlays %d accepted: %d from the control plane, %d of the host kept (%s)\n",
		s.Revision, len(s.Files), len(own), strings.Join(own, ", "))
	binPath := filepath.Join(o.Prefix, "bin", "monitoring-agent")
	out, err := o.Run(lk.File(), binPath, "update", "--prefix", o.Prefix, "--site-dir", stage)
	o.Out.Write(out)
	switch {
	case err == nil:
		return set("ok", "%s", lastLine(string(out)))
	case strings.Contains(string(out), "ROLLED BACK"):
		return set("rolled_back", "the new configuration did not start, the previous one runs again: %s", lastLine(string(out)))
	default:
		return set("failed", "nothing changed (%v): %s", err, lastLine(string(out)))
	}
}

// stageSite writes the new site.d into dir: the installed files without generate.SitePrefix (the host owner's,
// from --site-dir) and the control plane's set. It returns the names of the host owner's files.
func (o *Options) stageSite(dir string, files map[string]string) ([]string, error) {
	var own []string
	installed := filepath.Join(o.Prefix, "config", "site.d")
	ents, err := os.ReadDir(installed)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, generate.SitePrefix) || strings.HasPrefix(n, ".") || !e.Type().IsRegular() ||
			!(strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml")) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(installed, n))
		if err != nil {
			return nil, err
		}
		if err := writeRoot(filepath.Join(dir, n), b, 0o644); err != nil {
			return nil, err
		}
		own = append(own, n)
	}
	for n, y := range files { // names checked by CheckSite: no path parts
		if err := writeRoot(filepath.Join(dir, n), []byte(y), 0o644); err != nil {
			return nil, err
		}
	}
	sort.Strings(own)
	return own, nil
}
