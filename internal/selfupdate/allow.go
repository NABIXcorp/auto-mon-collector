package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
	"github.com/NABIXcorp/auto-mon-collector/internal/lockfile"
)

// The allowlist overlay from the control plane (v0.26.0), root's half. The request is the signed document
// (verified again in loadRequest); the host owner's switch and ceilings are answers.yaml agent.allow_edit, read here
// again; the overlay is checked again (generate.CheckAllowOverlay: root does not trust the agent). answers.yaml is
// never edited: the overlay is its own file (generate.AllowOverlayFile), so it can never touch the control-plane
// URL, its key, update or site. Then `monitoring-agent update` re-renders what depends on the allowlist (the prober
// unit gets CAP_NET_RAW for ping), with the smoke run and automatic rollback; a failed update puts the previous
// overlay file back.
//
//	verify -> switch -> bounds -> lock -> record -> write the overlay -> update --no-fetch -> agent/allow-result.json

// allowJob: the request carries an allowlist overlay root has not handled, and no new update or overlay set (one
// root job per document: those go first).
func allowJob(r request) bool {
	a := r.doc.Allow
	if a == nil || a.Revision <= r.last.AllowRevision {
		return false
	}
	return (r.doc.Update == nil || r.doc.Update.ID == r.last.ID) && !siteJob(r)
}

func (o *Options) runAllow(ctx context.Context, r request) (res agent.AllowResult) {
	a := r.doc.Allow
	res = agent.AllowResult{Revision: a.Revision, DocRevision: r.doc.Revision}
	defer func() {
		res.At = o.Now().Unix()
		if len(res.Detail) > 1000 {
			res.Detail = res.Detail[:1000]
		}
		fmt.Fprintf(o.Out, "self-update: allowlist %d: %s: %s\n", res.Revision, res.Result, res.Detail)
		if err := writeRoot(filepath.Join(o.Prefix, filepath.FromSlash(agent.AllowResultFile)), marshal(res), 0o644); err != nil {
			fmt.Fprintf(o.Out, "self-update: write %s: %v\n", agent.AllowResultFile, err)
		}
	}()
	set := func(result, format string, args ...any) agent.AllowResult {
		res.Result, res.Detail = result, fmt.Sprintf(format, args...)
		return res
	}
	edit := r.answers.Agent.AllowEdit
	if !edit.Allow {
		return set("refused", "allowlist changes from the control plane are off on this host (answers.yaml agent.allow_edit.allow)")
	}
	base, err := o.baseAllow(r.answers.Agent)
	if err != nil {
		return set("refused", "%v", err)
	}
	if err := generate.CheckAllowOverlay(a.Allow, edit, base); err != nil {
		return set("refused", "%v", err)
	}
	var data []byte // nil = remove the overlay
	if !a.Allow.Empty() {
		if data, err = generate.MarshalAllowOverlay(a.Allow, a.Revision); err != nil {
			return set("refused", "%v", err)
		}
	}
	lk, err := lockfile.Acquire(o.Prefix)
	if err != nil {
		return set("refused", "%v", err)
	}
	defer lk.Release()
	rec := record{ID: r.last.ID, Revision: r.doc.Revision, SiteRevision: r.last.SiteRevision, AllowRevision: a.Revision, At: o.Now().Unix()}
	if err := writeRoot(filepath.Join(o.Prefix, RecordFile), marshal(rec), 0o644); err != nil {
		return set("failed", "nothing changed: write %s: %v", RecordFile, err)
	}
	p := filepath.Join(o.Prefix, filepath.FromSlash(generate.AllowOverlayFile))
	prev, err := os.ReadFile(p)
	had := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return set("failed", "nothing changed: %v", err)
	}
	if err := putOverlay(p, data); err != nil {
		if rerr := putOverlay(p, keep(had, prev)); rerr != nil {
			return set("failed", "write %s: %v; RESTORING the previous one FAILED: %v", generate.AllowOverlayFile, err, rerr)
		}
		return set("failed", "nothing changed: write %s: %v", generate.AllowOverlayFile, err)
	}
	what := "written"
	if data == nil {
		what = "removed (empty overlay)"
	}
	fmt.Fprintf(o.Out, "self-update: allowlist %d accepted: %s %s; running `update`\n", a.Revision, generate.AllowOverlayFile, what)
	binPath := filepath.Join(o.Prefix, "bin", "monitoring-agent")
	// --no-fetch: the overlay changes the configuration only; the installed collector and prober stay
	out, err := o.Run(lk.File(), binPath, "update", "--prefix", o.Prefix, "--no-fetch")
	o.Out.Write(out)
	if err == nil {
		return set("ok", "%s", lastLine(string(out)))
	}
	// the engine has put its own files back (or changed nothing): the previous overlay goes back too
	if rerr := putOverlay(p, keep(had, prev)); rerr != nil {
		return set("failed", "update failed (%v): %s; RESTORING the previous %s FAILED: %v", err, lastLine(string(out)), generate.AllowOverlayFile, rerr)
	}
	if strings.Contains(string(out), "ROLLED BACK") {
		return set("rolled_back", "the new configuration did not start, the previous allowlist and configuration run again: %s", lastLine(string(out)))
	}
	return set("failed", "nothing changed (%v): %s", err, lastLine(string(out)))
}

// baseAllow: the effective allowlist without any overlay: the installed template + the answers' extras.
func (o *Options) baseAllow(ag *generate.Agent) (generate.Allow, error) {
	var tmpl generate.Allow
	p := filepath.Join(o.Prefix, filepath.FromSlash(generate.AllowFile))
	if _, err := os.Stat(p); err == nil {
		if tmpl, err = generate.LoadAllow(p); err != nil {
			return tmpl, err
		}
	}
	return tmpl.Merge(ag.Allow), nil
}

// keep: the previous file content, nil when there was none.
func keep(had bool, prev []byte) []byte {
	if !had {
		return nil
	}
	if prev == nil {
		return []byte{}
	}
	return prev
}

// putOverlay writes the overlay file (root 644), nil data = remove it.
func putOverlay(p string, data []byte) error {
	if data == nil {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return writeRoot(p, data, 0o644)
}
