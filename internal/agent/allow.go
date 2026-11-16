package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

// The allowlist overlay from the control plane (v0.26.0), the agent's half. Like an overlay set: the agent only
// checks the host owner's switch and the bounds (generate.CheckAllowOverlay), saves the whole signed document for
// root as the request (the same file and the same root unit: one job at a time) and reports root's result once.
// `monitoring-agent self-update` (root) verifies everything again, writes generate.AllowOverlayFile and runs
// `monitoring-agent update` (the prober unit gets CAP_NET_RAW for ping; smoke run; automatic rollback).

// AllowResultFile (below the prefix): root's result for an allowlist overlay (root 644), see AllowResult.
const AllowResultFile = "agent/allow-result.json"

// AllowResult is what root writes for an allowlist overlay. Result: ok | failed (nothing changed) | rolled_back (the
// new configuration did not start; the previous overlay and configuration are back) | refused (request, switch, bounds).
type AllowResult struct {
	Revision    int64  `json:"revision"`     // the overlay's revision
	DocRevision int64  `json:"doc_revision"` // the signed document it came in
	Result      string `json:"result"`
	Detail      string `json:"detail"`
	At          int64  `json:"at"`
}

// LoadAllowResult reads the result file; missing = none (zero value, nil error).
func LoadAllowResult(prefix string) (AllowResult, error) {
	var r AllowResult
	b, err := os.ReadFile(filepath.Join(prefix, filepath.FromSlash(AllowResultFile)))
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	if len(b) > 64<<10 {
		return r, fmt.Errorf("%s too large", AllowResultFile)
	}
	return r, json.Unmarshal(b, &r)
}

// prepareAllow: the agent's checks for a NEW overlay. ok = the request file is written and the unit may start.
func prepareAllow(prefix string, local Local, a *DocAllow, raw []byte) (st AllowStatus, ok bool) {
	st = AllowStatus{Revision: a.Revision}
	if !local.Agent.AllowEdit.Allow {
		st.Result, st.Detail = "refused", "allowlist changes from the control plane are off on this host (answers.yaml agent.allow_edit.allow)"
		return st, false
	}
	if a.Revision <= 0 {
		st.Result, st.Detail = "refused", "allowlist revision must be above 0"
		return st, false
	}
	if err := generate.CheckAllowOverlay(a.Allow, local.Agent.AllowEdit, local.Base); err != nil {
		st.Result, st.Detail = "refused", err.Error()
		return st, false
	}
	if err := writeAtomic(filepath.Join(prefix, filepath.FromSlash(UpdateRequestFile)), raw, 0o600); err != nil {
		st.Result, st.Detail = "failed", "save the request: "+err.Error()
		return st, false
	}
	return st, true
}

// startAllow starts the root unit without waiting (update + smoke run take about a minute).
func startAllow(run Runner, st AllowStatus) AllowStatus {
	if out, err := run("systemctl", "start", "--no-block", UpdateUnit); err != nil {
		st.Result, st.Detail = "failed", "starting "+UpdateUnit+" failed (polkit rule missing?): "+lastLine(out)
		return st
	}
	st.Result, st.Detail = "started", "handed to "+UpdateUnit+" (root re-verifies the request)"
	return st
}

// reportAllowResult sends root's allowlist result once (like reportSiteResult). false = ctx ended.
func reportAllowResult(ctx context.Context, cfg Config, cl *Client, st *State) bool {
	r, err := LoadAllowResult(cfg.Prefix)
	if err != nil {
		cfg.Log.Printf("agent: %s: %v", AllowResultFile, err)
		return true
	}
	if r.Revision == 0 || r.Revision == st.AllowReported {
		return true
	}
	s := Status{Revision: st.Revision, Result: "applied", Detail: fmt.Sprintf("allowlist %d: %s", r.Revision, r.Result), Versions: cfg.Versions,
		Allow: &AllowStatus{Revision: r.Revision, Result: r.Result, Detail: r.Detail}}
	var refused *RefusedError
	switch err := cl.Report(ctx, s); {
	case ctx.Err() != nil:
		return false
	case err == nil, errors.As(err, &refused):
		if err != nil {
			cfg.Log.Printf("agent: allowlist %d result: %v (not sent again)", r.Revision, err)
		}
		next := *st
		next.AllowReported = r.Revision
		if err := saveState(cfg.Prefix, next); err != nil {
			cfg.Log.Printf("agent: %s: %v", StateFile, err)
			return true
		}
		*st = next
		cfg.Log.Printf("agent: allowlist %d: %s reported", r.Revision, r.Result)
	default:
		cfg.Log.Printf("agent: allowlist %d result: %v (retried with the next poll)", r.Revision, err)
	}
	return true
}
