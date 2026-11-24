package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/diskscan"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

// Service re-scan (v0.32.0), the agent's half. The scan runs in the unit monitoring-scan (`monitoring-agent scan`:
// the installer's own service detection, writes only <prefix>/inventory.json: new content when the services
// changed, else only its mtime = the scan time = the inventory's services_at); the agent only decides WHEN (every 15 min, the first poll after its start, or a signed console request that carries nothing
// but an id) and starts the unit (polkit: start only). The new inventory.json reaches the control plane with the
// next inventory (inventoryBody re-reads it every poll and sends only a change). Only when answers.yaml
// agent.rescan.allow.
const (
	// ScanUnit is the oneshot unit that runs `monitoring-agent scan`.
	ScanUnit     = "monitoring-scan.service"
	rescanEvery  = 15 * time.Minute
	rescanBusy   = 5 * time.Minute  // a started scan counts as running at most this long (the unit's timeout is 4 min)
	rescanRetry  = 15 * time.Minute // a start that failed (e.g. the unit not linked yet) is tried again after this
	rescanReason = "handed to " + ScanUnit
)

// RescanRequest is the console's "scan the services now" in the signed document: only an id (reported back).
type RescanRequest struct {
	ID string `json:"id"`
}

// RescanStatus answers a request: started | busy (a scan runs; its inventory answers the request too) | refused |
// failed.
type RescanStatus struct {
	ID     string `json:"id"`
	Result string `json:"result"`
	Detail string `json:"detail,omitempty"`
}

// startRescan starts the unit without waiting.
func startRescan(run Runner) error {
	// allowed by the polkit rule monitoring-agent installs (this unit, verb start, this user only)
	if out, err := run("systemctl", "start", "--no-block", ScanUnit); err != nil {
		return fmt.Errorf("starting %s failed (polkit rule missing?): %s", ScanUnit, lastLine(out))
	}
	return nil
}

// rescanRunning: a scan was started less than rescanBusy ago and has not finished yet. Every completed scan sets the
// mtime of inventory.json (new content or not), so an mtime at or after the start = that scan is done; a request
// after it starts a new scan (the console waits for a newer services_at, which a "busy" answer would never bring).
func rescanRunning(prefix string, st State, now time.Time) bool {
	if st.RescanStarted == 0 || now.Sub(time.UnixMilli(st.RescanStarted)) >= rescanBusy {
		return false
	}
	if fi, err := os.Stat(filepath.Join(prefix, generate.InventoryFile)); err == nil && fi.ModTime().UnixMilli() >= st.RescanStarted {
		return false
	}
	return true
}

// rescanStamp: the start time in unix MILLISECONDS, always later than the previous one.
func rescanStamp(st State, now time.Time) int64 {
	return max(now.UnixMilli(), st.RescanStarted+1)
}

// rescanTick runs once per poll: start the scan when due (never started by this agent process, i.e. since boot, or
// the last start >= rescanEvery ago). A failed start is not a running scan; it is tried again after rescanRetry. It
// saves the state itself.
func rescanTick(cfg Config, allow bool, boot time.Time, st *State) {
	if !allow {
		return
	}
	now := cfg.Now()
	retryWait := st.RescanFailed > st.RescanStarted && now.Sub(time.UnixMilli(st.RescanFailed)) < rescanRetry
	if retryWait || rescanRunning(cfg.Prefix, *st, now) {
		return
	}
	reason := ""
	switch {
	case st.RescanStarted < boot.UnixMilli():
		reason = "agent start"
	case now.Sub(time.UnixMilli(st.RescanStarted)) >= rescanEvery:
		reason = "every 15 min"
	default:
		return
	}
	next := *st
	at := rescanStamp(*st, now)
	if err := startRescan(cfg.Run); err != nil {
		cfg.Log.Printf("agent: service scan: %v (tried again in %s)", err, rescanRetry)
		next.RescanFailed = at
	} else {
		cfg.Log.Printf("agent: service scan started (%s)", reason)
		next.RescanStarted = at
	}
	if err := saveState(cfg.Prefix, next); err != nil {
		cfg.Log.Printf("agent: %s: %v", StateFile, err)
		return
	}
	*st = next
}

// requestRescan answers a console request (a new id). next gets the id and, when started, the start time.
func requestRescan(cfg Config, allow bool, req *RescanRequest, next *State) RescanStatus {
	s := RescanStatus{ID: req.ID}
	next.RescanID = req.ID
	switch {
	case !diskscan.ValidID(req.ID): // the same id rule as the disk scan
		s.ID, s.Result, s.Detail = "", "refused", "rescan id: 8-64 characters A-Z a-z 0-9 _ -"
		return s
	case !allow:
		s.Result, s.Detail = "refused", "service re-scan is off on this host (answers.yaml agent.rescan.allow)"
		return s
	}
	now := cfg.Now()
	if rescanRunning(cfg.Prefix, *next, now) {
		s.Result, s.Detail = "busy", "a scan is running; the inventory follows"
		return s
	}
	at := rescanStamp(*next, now)
	if err := startRescan(cfg.Run); err != nil {
		s.Result, s.Detail = "failed", err.Error()
		return s
	}
	next.RescanStarted = at
	s.Result, s.Detail = "started", rescanReason
	return s
}
