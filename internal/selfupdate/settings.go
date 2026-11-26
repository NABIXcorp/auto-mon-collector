package selfupdate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
	"github.com/NABIXcorp/auto-mon-collector/internal/lockfile"
)

// The control plane's agent settings (v0.35.0), root's half. The request is the signed document (verified again in
// loadRequest); the host owner's consent is answers.yaml agent.settings.allow and a key the answers write themselves
// (pinned) is never set; the set is checked again (generate.CheckSettingsSet: root does not trust the agent).
// answers.yaml is never edited: the set is its own file (generate.SettingsFile), applied over the answers by the
// generator (generate.EffectiveAgent, answers win). Then `monitoring-agent update`: it does what an answers change of
// the same switch does (the disk scan / service scan units linked or unlinked, the polkit rule, DOCKER_MON, the
// generator's gates), with the smoke run and automatic rollback; a failed update puts the previous file back.
//
//	verify -> consent / keys / pinned -> lock -> record -> write the set -> update --no-fetch
//	-> agent/settings-result.json

// settingsJob: the request carries a set root has not handled, and no new update, overlay set, allowlist overlay or
// service switches (one root job per document: those go first).
func settingsJob(r request) bool {
	s := r.doc.Settings
	if s == nil || s.Revision <= r.last.SettingsRevision {
		return false
	}
	return (r.doc.Update == nil || r.doc.Update.ID == r.last.ID) && !siteJob(r) && !allowJob(r) && !servicesJob(r)
}

func (o *Options) runSettings(r request) (res agent.SettingsResult) {
	sv := r.doc.Settings
	res = agent.SettingsResult{Revision: sv.Revision, DocRevision: r.doc.Revision}
	defer func() {
		res.At = o.Now().Unix()
		if len(res.Detail) > 1000 {
			res.Detail = res.Detail[:1000]
		}
		fmt.Fprintf(o.Out, "self-update: settings %d: %s: %s\n", res.Revision, res.Result, res.Detail)
		if err := writeRoot(filepath.Join(o.Prefix, filepath.FromSlash(agent.SettingsResultFile)), marshal(res), 0o644); err != nil {
			fmt.Fprintf(o.Out, "self-update: write %s: %v\n", agent.SettingsResultFile, err)
		}
	}()
	set := func(result, format string, args ...any) agent.SettingsResult {
		res.Result, res.Detail = result, fmt.Sprintf(format, args...)
		return res
	}
	if err := generate.CheckSettingsSet(sv.Set, r.answers.Agent); err != nil {
		return set("refused", "%v", err)
	}
	var data []byte // nil = remove the set
	if len(sv.Set) > 0 {
		var err error
		if data, err = generate.MarshalSettingsOverlay(generate.SettingsOverlay{Revision: sv.Revision, Set: sv.Set}); err != nil {
			return set("refused", "%v", err)
		}
	}
	lk, err := lockfile.Acquire(o.Prefix)
	if err != nil {
		return set("refused", "%v", err)
	}
	defer lk.Release()
	rec := r.last
	rec.Revision, rec.SettingsRevision, rec.At = r.doc.Revision, sv.Revision, o.Now().Unix()
	if err := writeRoot(filepath.Join(o.Prefix, RecordFile), marshal(rec), 0o644); err != nil {
		return set("failed", "nothing changed: write %s: %v", RecordFile, err)
	}
	p := filepath.Join(o.Prefix, filepath.FromSlash(generate.SettingsFile))
	prev, err := os.ReadFile(p)
	had := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return set("failed", "nothing changed: %v", err)
	}
	if err := putOverlay(p, data); err != nil {
		if rerr := putOverlay(p, keep(had, prev)); rerr != nil {
			return set("failed", "write %s: %v; RESTORING the previous one FAILED: %v", generate.SettingsFile, err, rerr)
		}
		return set("failed", "nothing changed: write %s: %v", generate.SettingsFile, err)
	}
	what := "written (" + sv.Set.String() + ")"
	if data == nil {
		what = "removed (empty set)"
	}
	fmt.Fprintf(o.Out, "self-update: settings %d accepted: %s %s; running `update`\n", sv.Revision, generate.SettingsFile, what)
	binPath := filepath.Join(o.Prefix, "bin", "monitoring-agent")
	// --no-fetch: the settings change the configuration and the units only; the installed collector and prober stay
	out, err := o.Run(lk.File(), binPath, "update", "--prefix", o.Prefix, "--no-fetch")
	o.Out.Write(out)
	if err == nil {
		return set("applied", "%s", lastLine(string(out)))
	}
	// the engine has put its own files back (or changed nothing): the previous set goes back too
	if rerr := putOverlay(p, keep(had, prev)); rerr != nil {
		return set("failed", "update failed (%v): %s; RESTORING the previous %s FAILED: %v", err, lastLine(string(out)), generate.SettingsFile, rerr)
	}
	if strings.Contains(string(out), "ROLLED BACK") {
		return set("rolled_back", "the new configuration did not start, the previous settings and configuration run again: %s", lastLine(string(out)))
	}
	return set("failed", "nothing changed (%v): %s", err, lastLine(string(out)))
}
