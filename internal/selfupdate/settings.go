package selfupdate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/envfile"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
	"github.com/NABIXcorp/auto-mon-collector/internal/lockfile"
)

// The control plane's agent settings (v0.35.0), root's half. The request is the signed document (verified again in
// loadRequest); the host owner's consent is answers.yaml agent.settings.allow and a key the answers write themselves
// (pinned) is never set; the set is checked again (generate.CheckSettings: root does not trust the agent).
// answers.yaml is never edited: the set is its own file (generate.SettingsFile), applied over the answers by the
// generator (generate.ApplySettings, answers win). Then `monitoring-agent update`: it does what an answers change of
// the same switch does (the disk scan / service scan units linked or unlinked, the polkit rule, DOCKER_MON, the
// generator's gates), with the smoke run and automatic rollback; a failed update puts the previous file back.
// v0.36.0: + the groups' values (the effective answers must be valid). v0.37.0: + sealed passwords: root opens a
// password with a new id with its private key, writes it into secrets/collector.env (backup first) and runs the
// update with --restart; the file records only {key: id}; a failed update puts collector.env back too.
//
//	verify -> consent / keys / pinned / values / passwords -> open new passwords -> lock -> record -> write the set
//	-> collector.env (new passwords only) -> update --no-fetch [--restart] -> agent/settings-result.json

// settingsJob: the request carries a set root has not handled, and no new update, overlay set, allowlist overlay or
// service switches (one root job per document: those go first).
func settingsJob(r request) bool {
	s := r.doc.Settings
	if s == nil || s.Revision <= r.last.SettingsRevision {
		return false
	}
	return (r.doc.Update == nil || r.doc.Update.ID == r.last.ID) && !siteJob(r) && !allowJob(r) && !servicesJob(r)
}

const (
	collectorUnit = "monitoring-collector.service"
	// envBackup (below the prefix, root 600): collector.env before the last password a settings job wrote
	envBackup = "secrets/collector.env.before-settings"
)

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
		// v0.37.0: "set" / "not set" for the inventory (the agent cannot read collector.env); never a value
		if err := generate.WritePasswordState(o.Prefix); err != nil {
			fmt.Fprintf(o.Out, "self-update: write %s: %v\n", generate.PasswordStateFile, err)
		}
	}()
	set := func(result, format string, args ...any) agent.SettingsResult {
		res.Result, res.Detail = result, fmt.Sprintf(format, args...)
		return res
	}
	// v0.36.0: the switches and the groups' values (the effective answers must pass the answers validation);
	// v0.37.0: the passwords' keys, consent, ids and blob shapes
	if err := generate.CheckSettings(*sv, r.raw); err != nil {
		return set("refused", "%v", err)
	}
	p := filepath.Join(o.Prefix, filepath.FromSlash(generate.SettingsFile))
	installed, err := generate.LoadSettingsOverlay(p)
	if err != nil {
		installed = generate.SettingsOverlay{} // a broken file is replaced; every password is opened again
	}
	// v0.37.0: open the passwords with a new id (the same id = written before: not opened again, so a blob sealed to
	// an older host key does not block the rest of the set). Only the keys are ever printed.
	env, ids, written, err := o.openPasswords(sv.Passwords, installed.PasswordIDs)
	if err != nil {
		return set("refused", "%v", err)
	}
	var data []byte // nil = remove the set
	if ov := (generate.SettingsOverlay{Revision: sv.Revision, Set: sv.Set, Values: sv.Values, PasswordIDs: ids}); !ov.Empty() {
		if data, err = generate.MarshalSettingsOverlay(ov); err != nil {
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
	envRestore, err := o.writePasswords(env)
	if err != nil {
		if rerr := putOverlay(p, keep(had, prev)); rerr != nil {
			return set("failed", "%v; RESTORING the previous %s FAILED: %v", err, generate.SettingsFile, rerr)
		}
		return set("failed", "nothing changed: %v", err)
	}
	what := "written (" + sv.String() + ")"
	if data == nil {
		what = "removed (empty set)"
	}
	if len(written) > 0 {
		what += "; secrets/collector.env: " + strings.Join(written, ", ") + " written (backup " + envBackup + ")"
	}
	fmt.Fprintf(o.Out, "self-update: settings %d accepted: %s %s; running `update`\n", sv.Revision, generate.SettingsFile, what)
	binPath := filepath.Join(o.Prefix, "bin", "monitoring-agent")
	// --no-fetch: the settings change the configuration and the units only; the installed collector and prober stay.
	// --restart (v0.37.0): a new password changes no configuration file, but the units must read it.
	args := []string{"update", "--prefix", o.Prefix, "--no-fetch"}
	if len(written) > 0 {
		args = append(args, "--restart")
	}
	out, err := o.Run(lk.File(), binPath, args...)
	o.Out.Write(out)
	if err == nil {
		return set("applied", "%s", lastLine(string(out)))
	}
	// the engine has put its own files back (or changed nothing): the previous set and passwords go back too
	rerr := putOverlay(p, keep(had, prev))
	if envRestore != nil {
		if eerr := envRestore(); eerr != nil {
			rerr = errors.Join(rerr, eerr)
		} else if rout, xerr := o.Run(nil, "systemctl", "try-restart", collectorUnit); xerr != nil {
			// the units may have restarted with the new passwords: once more with the previous ones
			rerr = errors.Join(rerr, fmt.Errorf("restart %s with the previous passwords: %v %s", collectorUnit, xerr, lastLine(string(rout))))
		}
	}
	if rerr != nil {
		return set("failed", "update failed (%v): %s; RESTORING the previous settings FAILED: %v", err, lastLine(string(out)), rerr)
	}
	if strings.Contains(string(out), "ROLLED BACK") {
		return set("rolled_back", "the new configuration did not start, the previous settings and configuration run again: %s", lastLine(string(out)))
	}
	return set("failed", "nothing changed (%v): %s", err, lastLine(string(out)))
}

// openPasswords (v0.37.0): env = the collector.env values to write (ENV key -> value, never printed), ids = the
// {key: id} the file records, written = the keys opened now (sorted).
func (o *Options) openPasswords(pw map[string]generate.SealedPassword, installed map[string]string) (env, ids map[string]string, written []string, err error) {
	env, ids = map[string]string{}, map[string]string{}
	keys := make([]string, 0, len(pw))
	for k := range pw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var priv []byte
	for _, k := range keys {
		ids[k] = pw[k].ID
		if installed[k] == pw[k].ID {
			continue
		}
		if priv == nil {
			key, err := generate.LoadSealPriv(o.Prefix)
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil, nil, fmt.Errorf("settings: %s: this host has no settings key pair yet (%s; the next update makes it)", k, generate.SealKeyFile)
			}
			if err != nil {
				return nil, nil, nil, fmt.Errorf("settings: %v", err)
			}
			priv = key.Bytes()
		}
		plain, err := generate.Open(priv, k, pw[k].Sealed)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("settings: %s: %v", k, err)
		}
		if err := generate.CheckPlainPassword(plain); err != nil {
			return nil, nil, nil, fmt.Errorf("settings: %s: %v", k, err)
		}
		env[generate.PasswordEnv[k]] = string(plain)
		written = append(written, k)
	}
	return env, ids, written, nil
}

// writePasswords (v0.37.0): collector.env with the new values (backup first: envBackup, root 600). restore puts
// the previous file back (nil = nothing written).
func (o *Options) writePasswords(env map[string]string) (restore func() error, err error) {
	if len(env) == 0 {
		return nil, nil
	}
	p := filepath.Join(o.Prefix, "secrets", "collector.env")
	prev, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read secrets/collector.env: %v", err)
	}
	if err := writeRoot(filepath.Join(o.Prefix, filepath.FromSlash(envBackup)), prev, 0o600); err != nil {
		return nil, fmt.Errorf("backup secrets/collector.env: %v", err)
	}
	next := prev
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if next, err = envfile.Set(next, k, env[k]); err != nil {
			return nil, fmt.Errorf("secrets/collector.env: %s: %v", k, err) // the error never holds the value
		}
	}
	if err := writeRoot(p, next, 0o600); err != nil {
		return nil, fmt.Errorf("write secrets/collector.env: %v", err)
	}
	return func() error { return writeRoot(p, prev, 0o600) }, nil
}
