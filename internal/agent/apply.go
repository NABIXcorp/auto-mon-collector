package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

// Runner runs a program and returns its combined output (replaced in tests).
type Runner func(name string, args ...string) ([]byte, error)

// Applier writes a probe list into <prefix>/config/cloudprober/ (the only files the agent may change).
type Applier struct {
	Prefix string
	Run    Runner
}

func (a *Applier) dir() string { return filepath.Join(a.Prefix, filepath.FromSlash(generate.ProbeDir)) }

var targetFileRE = regexp.MustCompile(`^cloudprober-[a-z0-9_-]{1,40}\.json$`)

// Apply: answers probes + the control plane's list -> Cloudprober files, `cloudprober --configtest` on a staged
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
		if !targetFileRE.MatchString(n) {
			return false, fmt.Errorf("target file name %q", n)
		}
		if err := os.WriteFile(filepath.Join(stage, n), b, 0o644); err != nil {
			return false, fmt.Errorf("stage: %w", err)
		}
	}
	cfgStage := filepath.Join(stage, "cloudprober.cfg")
	if err := os.WriteFile(cfgStage, staged, 0o644); err != nil {
		return false, fmt.Errorf("stage: %w", err)
	}
	if out, err := a.Run(filepath.Join(a.Prefix, "bin", "cloudprober"), "--configtest", "--config_file="+cfgStage); err != nil {
		return false, reject("cloudprober --configtest failed: %s", lastLine(out))
	}
	cfg := bytes.ReplaceAll(pf.Config, []byte(generate.ProbePrefix), []byte(filepath.ToSlash(a.Prefix)))
	old, _ := os.ReadFile(filepath.Join(dir, "cloudprober.cfg"))
	for n, b := range pf.Targets {
		if err := writeAtomic(filepath.Join(dir, n), b, 0o644); err != nil {
			return false, err
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, en := range entries {
		if _, want := pf.Targets[en.Name()]; !want && targetFileRE.MatchString(en.Name()) {
			if err := os.Remove(filepath.Join(dir, en.Name())); err != nil {
				return false, err
			}
		}
	}
	if bytes.Equal(old, cfg) {
		return false, nil
	}
	if err := writeAtomic(filepath.Join(dir, "cloudprober.cfg"), cfg, 0o644); err != nil {
		return false, err
	}
	// allowed by the polkit rule amc installs (this unit, this verb, this user only)
	if out, err := a.Run("systemctl", "restart", "monitoring-cloudprober.service"); err != nil {
		return false, fmt.Errorf("files written, but restarting Cloudprober failed (polkit rule missing?): %s", lastLine(out))
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
	tmp, err := os.CreateTemp(filepath.Dir(p), ".amc-agent-*")
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

// State is what the agent applied last (<prefix>/agent/state.json). `amc plan` / `amc apply` read it, so the files
// they generate are the agent's (no drift, no undoing the agent's last change).
type State struct {
	Revision int64           `json:"revision"`
	Probes   generate.Probes `json:"probes"`
	At       int64           `json:"applied_at"`
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

func saveState(prefix string, s State) error {
	s.At = time.Now().Unix()
	b, _ := json.MarshalIndent(s, "", "  ")
	return writeAtomic(filepath.Join(prefix, filepath.FromSlash(StateFile)), append(b, '\n'), 0o640)
}
