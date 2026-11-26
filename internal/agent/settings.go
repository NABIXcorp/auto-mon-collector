package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

// The control plane's agent settings (v0.35.0), the agent's half. Like the service switches: the agent only checks
// the host owner's consent list, the key list and the pinned keys (generate.CheckSettingsSet), saves the whole signed
// document for root as the request (the same file and the same root unit: one job at a time) and reports root's
// result once. `monitoring-agent self-update` (root) verifies everything again, writes generate.SettingsFile and runs
// `monitoring-agent update` (units, polkit rule, generator gates; smoke run; automatic rollback).

// SettingsResultFile (below the prefix): root's result for a settings set (root 644), see SettingsResult.
const SettingsResultFile = "agent/settings-result.json"

// SettingsResult is what root writes for a set. Result: applied | failed (nothing changed) | rolled_back (the new
// configuration did not start; the previous set and configuration are back) | refused (request, consent, keys).
type SettingsResult struct {
	Revision    int64  `json:"revision"`     // the set's revision
	DocRevision int64  `json:"doc_revision"` // the signed document it came in
	Result      string `json:"result"`
	Detail      string `json:"detail"`
	At          int64  `json:"at"`
}

// LoadSettingsResult reads the result file; missing = none (zero value, nil error).
func LoadSettingsResult(prefix string) (SettingsResult, error) {
	var r SettingsResult
	b, err := os.ReadFile(filepath.Join(prefix, filepath.FromSlash(SettingsResultFile)))
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	if len(b) > 64<<10 {
		return r, fmt.Errorf("%s too large", SettingsResultFile)
	}
	return r, json.Unmarshal(b, &r)
}

// prepareSettings: the agent's checks for a NEW set. ok = the request file is written and the unit may start.
func prepareSettings(prefix string, local Local, sv *generate.SettingsOverlay, raw []byte) (st SettingsStatus, ok bool) {
	st = SettingsStatus{Revision: sv.Revision}
	if sv.Revision <= 0 {
		st.Result, st.Detail = "refused", "settings revision must be above 0"
		return st, false
	}
	if err := generate.CheckSettingsSet(sv.Set, &local.Agent); err != nil {
		st.Result, st.Detail = "refused", err.Error()
		return st, false
	}
	if err := writeAtomic(filepath.Join(prefix, filepath.FromSlash(UpdateRequestFile)), raw, 0o600); err != nil {
		st.Result, st.Detail = "failed", "save the request: "+err.Error()
		return st, false
	}
	return st, true
}

// startSettings starts the root unit without waiting (update + smoke run take about a minute).
func startSettings(run Runner, st SettingsStatus) SettingsStatus {
	if out, err := run("systemctl", "start", "--no-block", UpdateUnit); err != nil {
		st.Result, st.Detail = "failed", "starting "+UpdateUnit+" failed (polkit rule missing?): "+lastLine(out)
		return st
	}
	st.Result, st.Detail = "started", "handed to "+UpdateUnit+" (root re-verifies the request)"
	return st
}

// reportSettingsResult sends root's result for a set once (like reportServicesResult). false = ctx ended.
func reportSettingsResult(ctx context.Context, cfg Config, cl *Client, st *State) bool {
	r, err := LoadSettingsResult(cfg.Prefix)
	if err != nil {
		cfg.Log.Printf("agent: %s: %v", SettingsResultFile, err)
		return true
	}
	if r.Revision == 0 || r.Revision == st.SettingsReported {
		return true
	}
	s := Status{Revision: st.Revision, Result: "applied", Detail: fmt.Sprintf("settings %d: %s", r.Revision, r.Result), Versions: cfg.Versions,
		Settings: &SettingsStatus{Revision: r.Revision, Result: r.Result, Detail: r.Detail}}
	var refused *RefusedError
	switch err := cl.Report(ctx, s); {
	case ctx.Err() != nil:
		return false
	case err == nil, errors.As(err, &refused):
		if err != nil {
			cfg.Log.Printf("agent: settings %d result: %v (not sent again)", r.Revision, err)
		}
		next := *st
		next.SettingsReported = r.Revision
		if err := saveState(cfg.Prefix, next); err != nil {
			cfg.Log.Printf("agent: %s: %v", StateFile, err)
			return true
		}
		*st = next
		cfg.Log.Printf("agent: settings %d: %s reported", r.Revision, r.Result)
	default:
		cfg.Log.Printf("agent: settings %d result: %v (retried with the next poll)", r.Revision, err)
	}
	return true
}

// invSettings: the settings part of the inventory.
type invSettings struct {
	Edit   []string                  // answers agent.settings.allow (nil = no consent)
	Pinned []string                  // never nil
	CP     *generate.SettingsOverlay // nil = no consent
}

// localSettings: the inventory's settings part from the host owner's side (Local.Agent keeps the pinned keys).
func localSettings(l Local) invSettings {
	s := invSettings{Pinned: l.Agent.Pinned()}
	if len(l.Agent.Settings.Allow) == 0 {
		return s
	}
	s.Edit = append([]string{}, l.Agent.Settings.Allow...)
	sort.Strings(s.Edit)
	cp := l.SettingsCP
	if cp.Set == nil {
		cp.Set = generate.SettingsSet{}
	}
	s.CP = &cp
	return s
}
