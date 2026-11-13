package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NABIXcorp/auto-mon-collector/assets"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

// Runner runs a program and returns its combined output (replaced in tests).
type Runner func(name string, args ...string) ([]byte, error)

// Applier writes a probe list into <prefix>/config/prober/ (the only files the agent may change).
type Applier struct {
	Prefix string
	Run    Runner
}

func (a *Applier) dir() string { return filepath.Join(a.Prefix, filepath.FromSlash(generate.ProbeDir)) }

// Apply: answers probes + the control plane's list -> prober files, `monitoring-prober --configtest` on a staged
// copy first, then the target files, then the config; Cloudprober restarts only when its config changed (target
// files are re-read by Cloudprober itself). On an error nothing of the installed files has changed, except when the
// restart fails (then the files are in place and the error says so).
func (a *Applier) Apply(local, remote generate.Probes) (restarted bool, err error) {
	merged := generate.MergeProbes(local, remote)
	if err := merged.Validate(); err != nil {
		return false, reject("with the answers' own probes: %v", err)
	}
	pf := generate.ProbeFilesFor(merged, true)
	dir := a.dir()
	stage, err := os.MkdirTemp(dir, ".stage-")
	if err != nil {
		return false, fmt.Errorf("stage: %w", err)
	}
	defer os.RemoveAll(stage)
	token := generate.ProbePrefix + "/" + generate.ProbeDir
	staged := bytes.ReplaceAll(pf.Config, []byte(token), []byte(filepath.ToSlash(stage)))
	for n, b := range pf.Targets {
		if !generate.ProbeTargetRE.MatchString(n) {
			return false, fmt.Errorf("target file name %q", n)
		}
		if err := os.WriteFile(filepath.Join(stage, n), b, 0o644); err != nil {
			return false, fmt.Errorf("stage: %w", err)
		}
	}
	cfgStage := filepath.Join(stage, generate.ProbeConfig)
	if err := os.WriteFile(cfgStage, staged, 0o644); err != nil {
		return false, fmt.Errorf("stage: %w", err)
	}
	if out, err := a.Run(filepath.Join(a.Prefix, "bin", "monitoring-prober"), "--configtest", "--config_file="+cfgStage); err != nil {
		return false, reject("monitoring-prober --configtest failed: %s", lastLine(out))
	}
	cfg := bytes.ReplaceAll(pf.Config, []byte(generate.ProbePrefix), []byte(filepath.ToSlash(a.Prefix)))
	old, _ := os.ReadFile(filepath.Join(dir, generate.ProbeConfig))
	for n, b := range pf.Targets {
		if err := writeAtomic(filepath.Join(dir, n), b, 0o644); err != nil {
			return false, err
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, en := range entries {
		if _, want := pf.Targets[en.Name()]; !want && generate.ProbeTargetRE.MatchString(en.Name()) {
			if err := os.Remove(filepath.Join(dir, en.Name())); err != nil {
				return false, err
			}
		}
	}
	if bytes.Equal(old, cfg) {
		return false, nil
	}
	if err := writeAtomic(filepath.Join(dir, generate.ProbeConfig), cfg, 0o644); err != nil {
		return false, err
	}
	// allowed by the polkit rule monitoring-agent installs (this unit, this verb, this user only)
	if out, err := a.Run("systemctl", "restart", assets.ProbeUnit+".service"); err != nil {
		return false, fmt.Errorf("files written, but restarting monitoring-prober failed (polkit rule missing?): %s", lastLine(out))
	}
	return true, nil
}

func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	s := lines[len(lines)-1]
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

func writeAtomic(p string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(p), ".monitoring-agent-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), mode)
	}
	if err == nil {
		err = os.Rename(tmp.Name(), p)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// State is what the agent applied last (<prefix>/agent/state.json). `monitoring-agent plan` / `monitoring-agent apply` read it, so the files
// they generate are the agent's (no drift, no undoing the agent's last change).
type State struct {
	Revision int64           `json:"revision"`
	Probes   generate.Probes `json:"probes"`
	At       int64           `json:"applied_at"`
	// v0.16.0: the last update request handled (never handled twice) and the last root result reported
	UpdateID       string `json:"update_id,omitempty"`
	UpdateReported string `json:"update_reported,omitempty"`
	// v0.23.0: the last overlay set handed to root and the last root result reported (site revisions)
	SiteRevision int64 `json:"site_revision,omitempty"`
	SiteReported int64 `json:"site_reported,omitempty"`
}

// StateFile below the prefix.
const StateFile = "agent/state.json"

// LoadState reads the state; missing = nothing applied yet.
func LoadState(prefix string) (State, error) {
	var s State
	b, err := os.ReadFile(filepath.Join(prefix, filepath.FromSlash(StateFile)))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

// saveState writes s as given (the caller sets At when it applied a revision).
func saveState(prefix string, s State) error {
	b, _ := json.MarshalIndent(s, "", "  ")
	return writeAtomic(filepath.Join(prefix, filepath.FromSlash(StateFile)), append(b, '\n'), 0o640)
}

// VersionKey: this agent's own version in the versions it reports (v0.20.0).
const VersionKey = "monitoring-agent"
