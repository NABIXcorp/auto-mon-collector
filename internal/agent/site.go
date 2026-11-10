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

// Collector overlays from the control plane (v0.23.0), the agent's half. As with an update, the agent only does
// cheap checks (the host owner's switch, the catalog), saves the whole signed document for root as the request
// (the same file and the same root unit: one job at a time) and reports root's result once.
// `monitoring-agent self-update` (root) verifies everything again, installs the set below config/site.d/ and runs
// plan + smoke run + apply with automatic rollback (`monitoring-agent update`).

// SiteResultFile (below the prefix): root's result for an overlay set (root 644), see SiteResult.
const SiteResultFile = "agent/site-result.json"

// SiteResult is what root writes for an overlay set. Result: ok | failed (nothing changed) | rolled_back (the new
// configuration did not start; the previous one runs again) | refused (request, switch or catalog).
type SiteResult struct {
	Revision    int64  `json:"revision"`     // the overlay set's revision
	DocRevision int64  `json:"doc_revision"` // the signed document it came in
	Result      string `json:"result"`
	Detail      string `json:"detail"`
	At          int64  `json:"at"`
}

// LoadSiteResult reads the result file; missing = none (zero value, nil error).
func LoadSiteResult(prefix string) (SiteResult, error) {
	var r SiteResult
	b, err := os.ReadFile(filepath.Join(prefix, filepath.FromSlash(SiteResultFile)))
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	if len(b) > 64<<10 {
		return r, fmt.Errorf("%s too large", SiteResultFile)
	}
	return r, json.Unmarshal(b, &r)
}

// prepareSite: the agent's checks for a NEW overlay set. ok = the request file is written and the unit may start.
func prepareSite(prefix string, pol generate.AgentSite, s *SiteRequest, raw []byte) (st SiteStatus, ok bool) {
	st = SiteStatus{Revision: s.Revision}
	if !pol.Allow {
		st.Result, st.Detail = "refused", "overlays from the control plane are off on this host (answers.yaml agent.site.allow)"
		return st, false
	}
	if s.Revision <= 0 {
		st.Result, st.Detail = "refused", "overlay revision must be above 0"
		return st, false
	}
	if err := generate.CheckSite(s.Files); err != nil {
		st.Result, st.Detail = "refused", err.Error()
		return st, false
	}
	if err := writeAtomic(filepath.Join(prefix, filepath.FromSlash(UpdateRequestFile)), raw, 0o600); err != nil {
		st.Result, st.Detail = "failed", "save the request: "+err.Error()
		return st, false
	}
	return st, true
}

// startSite starts the root unit without waiting (plan + smoke run + apply take about a minute).
func startSite(run Runner, st SiteStatus) SiteStatus {
	if out, err := run("systemctl", "start", "--no-block", UpdateUnit); err != nil {
		st.Result, st.Detail = "failed", "starting "+UpdateUnit+" failed (polkit rule missing?): "+lastLine(out)
		return st
	}
	st.Result, st.Detail = "started", "handed to "+UpdateUnit+" (root re-verifies the request)"
	return st
}

// reportSiteResult sends root's overlay result once (like reportUpdateResult). false = ctx ended.
func reportSiteResult(ctx context.Context, cfg Config, cl *Client, st *State) bool {
	r, err := LoadSiteResult(cfg.Prefix)
	if err != nil {
		cfg.Log.Printf("agent: %s: %v", SiteResultFile, err)
		return true
	}
	if r.Revision == 0 || r.Revision == st.SiteReported {
		return true
	}
	s := Status{Revision: st.Revision, Result: "applied", Detail: fmt.Sprintf("overlays %d: %s", r.Revision, r.Result), Versions: cfg.Versions,
		Site: &SiteStatus{Revision: r.Revision, Result: r.Result, Detail: r.Detail}}
	var refused *RefusedError
	switch err := cl.Report(ctx, s); {
	case ctx.Err() != nil:
		return false
	case err == nil, errors.As(err, &refused):
		if err != nil {
			cfg.Log.Printf("agent: overlays %d result: %v (not sent again)", r.Revision, err)
		}
		next := *st
		next.SiteReported = r.Revision
		if err := saveState(cfg.Prefix, next); err != nil {
			cfg.Log.Printf("agent: %s: %v", StateFile, err)
			return true
		}
		*st = next
		cfg.Log.Printf("agent: overlays %d: %s reported", r.Revision, r.Result)
	default:
		cfg.Log.Printf("agent: overlays %d result: %v (retried with the next poll)", r.Revision, err)
	}
	return true
}
