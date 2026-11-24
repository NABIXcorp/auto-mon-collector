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

// The control plane's service switches (v0.33.0), the agent's half. Like the allowlist overlay: the agent only
// checks the host owner's switch, the kind list and the bounds (generate.CheckServicesSet), saves the whole signed
// document for root as the request (the same file and the same root unit: one job at a time) and reports root's
// result once. `monitoring-agent self-update` (root) verifies everything again, checks that the service answers on
// 127.0.0.1, writes generate.ServicesFile and runs `monitoring-agent update` (smoke run; automatic rollback).

// ServicesResultFile (below the prefix): root's result for a service switch set (root 644), see ServicesResult.
const ServicesResultFile = "agent/services-result.json"

// ServicesResult is what root writes for a set. Result: applied | failed (nothing changed) | rolled_back (the new
// configuration did not start; the previous set and configuration are back) | refused (request, switch, kinds,
// the service does not answer).
type ServicesResult struct {
	Revision    int64  `json:"revision"`     // the set's revision
	DocRevision int64  `json:"doc_revision"` // the signed document it came in
	Result      string `json:"result"`
	Detail      string `json:"detail"`
	At          int64  `json:"at"`
}

// LoadServicesResult reads the result file; missing = none (zero value, nil error).
func LoadServicesResult(prefix string) (ServicesResult, error) {
	var r ServicesResult
	b, err := os.ReadFile(filepath.Join(prefix, filepath.FromSlash(ServicesResultFile)))
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	if len(b) > 64<<10 {
		return r, fmt.Errorf("%s too large", ServicesResultFile)
	}
	return r, json.Unmarshal(b, &r)
}

// prepareServices: the agent's checks for a NEW set. ok = the request file is written and the unit may start.
func prepareServices(prefix string, local Local, sv *generate.ServicesOverlay, raw []byte) (st ServicesStatus, ok bool) {
	st = ServicesStatus{Revision: sv.Revision}
	if sv.Revision <= 0 {
		st.Result, st.Detail = "refused", "services revision must be above 0"
		return st, false
	}
	if err := generate.CheckServicesSet(sv.Set, local.Agent.ServicesEdit, local.Services); err != nil {
		st.Result, st.Detail = "refused", err.Error()
		return st, false
	}
	if err := writeAtomic(filepath.Join(prefix, filepath.FromSlash(UpdateRequestFile)), raw, 0o600); err != nil {
		st.Result, st.Detail = "failed", "save the request: "+err.Error()
		return st, false
	}
	return st, true
}

// startServices starts the root unit without waiting (checks + update + smoke run take about a minute).
func startServices(run Runner, st ServicesStatus) ServicesStatus {
	if out, err := run("systemctl", "start", "--no-block", UpdateUnit); err != nil {
		st.Result, st.Detail = "failed", "starting "+UpdateUnit+" failed (polkit rule missing?): "+lastLine(out)
		return st
	}
	st.Result, st.Detail = "started", "handed to "+UpdateUnit+" (root re-verifies the request)"
	return st
}

// reportServicesResult sends root's result for a set once (like reportAllowResult). false = ctx ended.
func reportServicesResult(ctx context.Context, cfg Config, cl *Client, st *State) bool {
	r, err := LoadServicesResult(cfg.Prefix)
	if err != nil {
		cfg.Log.Printf("agent: %s: %v", ServicesResultFile, err)
		return true
	}
	if r.Revision == 0 || r.Revision == st.ServicesReported {
		return true
	}
	s := Status{Revision: st.Revision, Result: "applied", Detail: fmt.Sprintf("services %d: %s", r.Revision, r.Result), Versions: cfg.Versions,
		Services: &ServicesStatus{Revision: r.Revision, Result: r.Result, Detail: r.Detail}}
	var refused *RefusedError
	switch err := cl.Report(ctx, s); {
	case ctx.Err() != nil:
		return false
	case err == nil, errors.As(err, &refused):
		if err != nil {
			cfg.Log.Printf("agent: services %d result: %v (not sent again)", r.Revision, err)
		}
		next := *st
		next.ServicesReported = r.Revision
		if err := saveState(cfg.Prefix, next); err != nil {
			cfg.Log.Printf("agent: %s: %v", StateFile, err)
			return true
		}
		*st = next
		cfg.Log.Printf("agent: services %d: %s reported", r.Revision, r.Result)
	default:
		cfg.Log.Printf("agent: services %d result: %v (retried with the next poll)", r.Revision, err)
	}
	return true
}

// invServices: the installed set for the inventory (never nil: revision 0 + {} = none)
func invServices(prefix string, ag generate.Agent) *generate.ServicesOverlay {
	ov, err := generate.LocalServices(&ag, prefix)
	if err != nil || ov.Set == nil {
		ov.Set = generate.ServicesSet{}
	}
	return &ov
}
