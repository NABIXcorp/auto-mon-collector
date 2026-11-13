package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

// Remote monitoring-agent update (v0.16.0), the agent's half. The agent is NOT trusted with the update: it only does cheap
// checks, saves the whole signed document for root and starts the root oneshot unit monitoring-update (polkit:
// monitoring-agent may start that unit, nothing else). `monitoring-agent self-update` (root) verifies everything again itself
// (internal/selfupdate) and writes the result, which the agent reports once.
const (
	// UpdateRequestFile (below the prefix): the whole signed document with "update" (monitoring-agent 600; root reads it).
	UpdateRequestFile = "agent/update-request.json"
	// UpdateResultFile (below the prefix): root's result (root 644), see UpdateResult.
	UpdateResultFile = "agent/update-result.json"
	// UpdateUnit is the root oneshot unit that runs `monitoring-agent self-update`.
	UpdateUnit = "monitoring-update.service"
)

// UpdateResult is what `monitoring-agent self-update` writes. Result: ok | failed (nothing changed) | rolled_back (the new
// binary was installed but did not pass; the previous one is back) | refused (request or policy not accepted).
type UpdateResult struct {
	ID       string `json:"id"`
	From     string `json:"from"`
	To       string `json:"to"`
	Result   string `json:"result"`
	Detail   string `json:"detail"`
	At       int64  `json:"at"`
	Revision int64  `json:"revision,omitempty"`
}

// LoadUpdateResult reads the result file; missing = none (zero value, nil error).
func LoadUpdateResult(prefix string) (UpdateResult, error) {
	var r UpdateResult
	b, err := os.ReadFile(filepath.Join(prefix, filepath.FromSlash(UpdateResultFile)))
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	if len(b) > 64<<10 {
		return r, fmt.Errorf("%s too large", UpdateResultFile)
	}
	return r, json.Unmarshal(b, &r)
}

// prepareUpdate: the agent's checks for a NEW update request (u != nil, id not handled yet). ok = the request file
// is written and the unit may be started; otherwise st is the answer to report ("refused" / "failed").
func prepareUpdate(prefix string, pol generate.AgentUpdate, running string, u *UpdateRequest, raw []byte) (st UpdateStatus, ok bool) {
	st = UpdateStatus{ID: u.ID, From: running, To: u.Version}
	if !ValidUpdateID(u.ID) {
		st.Result, st.Detail = "refused", "update id: 8-64 characters A-Z a-z 0-9 _ -"
		st.ID = "" // not echoed: it is not a valid id
		return st, false
	}
	if err := pol.Check(running, u.Version); err != nil {
		st.Result, st.Detail = "refused", err.Error()
		return st, false
	}
	if err := writeAtomic(filepath.Join(prefix, filepath.FromSlash(UpdateRequestFile)), raw, 0o600); err != nil {
		st.Result, st.Detail = "failed", "save the request: "+err.Error()
		return st, false
	}
	return st, true
}

// startUpdate starts the root unit without waiting for it (it runs up to 15 min and restarts this agent).
func startUpdate(run Runner, st UpdateStatus) UpdateStatus {
	// allowed by the polkit rule monitoring-agent installs (this unit, verb start, this user only)
	if out, err := run("systemctl", "start", "--no-block", UpdateUnit); err != nil {
		st.Result, st.Detail = "failed", "starting "+UpdateUnit+" failed (polkit rule missing?): "+lastLine(out)
		return st
	}
	st.Result, st.Detail = "started", "handed to "+UpdateUnit+" (root re-verifies the request)"
	return st
}
