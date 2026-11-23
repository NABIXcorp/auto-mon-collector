package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/diskscan"
)

// Disk scan (v0.29.0), the agent's half. The scan itself runs in the unit monitoring-diskscan (`monitoring-agent
// disk-scan`, read-only, CAP_DAC_READ_SEARCH, no network); the agent only decides WHEN (daily, a disk >= 85 % full,
// or a signed console request that carries nothing but an id), starts the unit (polkit: start only) and uploads the
// result file (POST v1/diskscan). Only when answers.yaml agent.disk_scan.allow.
const (
	// DiskScanUnit is the oneshot unit that runs `monitoring-agent disk-scan`.
	DiskScanUnit    = "monitoring-diskscan.service"
	diskScanDaily   = 24 * time.Hour
	diskScanFullGap = 6 * time.Hour    // a full disk starts a scan at most every 6 h
	diskScanBusy    = 11 * time.Minute // a started scan counts as running this long (the unit's timeout)
	diskScanFull    = 85.0             // percent
)

// DiskScanRequest is the console's "scan now" in the signed document: only an id (reported back with the result).
type DiskScanRequest struct {
	ID string `json:"id"`
}

// DiskScanStatus answers a request: started | busy (a scan runs; its result answers the request too) | refused | failed.
type DiskScanStatus struct {
	ID     string `json:"id"`
	Result string `json:"result"`
	Detail string `json:"detail,omitempty"`
}

// usedPercent and nowDiskScan are replaced in tests.
var usedPercent = diskscan.UsedPercent

// startDiskScan writes the trigger and starts the unit without waiting (it runs up to 11 min).
func startDiskScan(prefix string, run Runner, t diskscan.Trigger) error {
	if err := diskscan.WriteTrigger(prefix, t); err != nil {
		return err
	}
	// allowed by the polkit rule monitoring-agent installs (this unit, verb start, this user only)
	if out, err := run("systemctl", "start", "--no-block", DiskScanUnit); err != nil {
		return fmt.Errorf("starting %s failed (polkit rule missing?): %s", DiskScanUnit, lastLine(out))
	}
	return nil
}

// diskScanRunning: a scan was started less than diskScanBusy ago and the result file does not answer that start yet
// (its trigger_at is the time the agent wrote into the trigger).
func diskScanRunning(st State, triggerAt int64, now time.Time) bool {
	return st.DiskScanStarted > 0 && triggerAt != st.DiskScanStarted && now.Sub(time.UnixMilli(st.DiskScanStarted)) < diskScanBusy
}

// stamp: the trigger time of a new start in unix MILLISECONDS, always later than the previous one (the result
// file names it, so two starts in the same second stay apart).
func stamp(st State, now time.Time) int64 {
	return max(now.UnixMilli(), st.DiskScanStarted+1)
}

// loadDiskScanResult reads the result file (raw JSON), its finish time and trigger time; missing = (nil, 0, 0, nil).
func loadDiskScanResult(prefix string) ([]byte, int64, int64, error) {
	b, err := os.ReadFile(filepath.Join(prefix, filepath.FromSlash(diskscan.ResultFile)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, 0, nil
	}
	if err != nil {
		return nil, 0, 0, err
	}
	if len(b) > diskscan.MaxResult {
		return nil, 0, 0, fmt.Errorf("%s too large (%d bytes)", diskscan.ResultFile, len(b))
	}
	var r struct {
		Finished  int64 `json:"finished_at"`
		TriggerAt int64 `json:"trigger_at"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, 0, 0, fmt.Errorf("%s: %v", diskscan.ResultFile, err)
	}
	return b, r.Finished, r.TriggerAt, nil
}

// diskScanTick runs once per poll: upload a new result, then start a daily / full-disk scan when due. It saves
// the state itself. false = ctx ended.
func diskScanTick(ctx context.Context, cfg Config, cl *Client, allow bool, st *State) bool {
	if !allow {
		return true
	}
	body, finished, trig, err := loadDiskScanResult(cfg.Prefix)
	if err != nil {
		cfg.Log.Printf("agent: disk scan: %v", err)
	}
	next := *st
	if body != nil && finished > st.DiskScanSent {
		var refused *RefusedError
		switch err := cl.SendDiskScan(ctx, body); {
		case ctx.Err() != nil:
			return false
		case err == nil, errors.As(err, &refused):
			if err != nil {
				cfg.Log.Printf("agent: disk scan result: %v (not sent again)", err)
			} else {
				cfg.Log.Printf("agent: disk scan result sent (%d bytes)", len(body))
			}
			next.DiskScanSent = finished
		default:
			cfg.Log.Printf("agent: disk scan result: %v (retried with the next poll)", err)
		}
	}
	now := cfg.Now()
	if !diskScanRunning(*st, trig, now) {
		since := now.Sub(time.UnixMilli(st.DiskScanStarted))
		reason := ""
		if st.DiskScanStarted == 0 || since >= diskScanDaily {
			reason = "daily"
		} else if since >= diskScanFullGap {
			if p, at, err := usedPercent(); err == nil && p >= diskScanFull {
				reason = "full"
				cfg.Log.Printf("agent: %s is %.0f %% full: disk scan", at, p)
			}
		}
		if reason != "" {
			at := stamp(*st, now)
			if err := startDiskScan(cfg.Prefix, cfg.Run, diskscan.Trigger{Reason: reason, At: at}); err != nil {
				cfg.Log.Printf("agent: disk scan: %v", err)
			} else {
				cfg.Log.Printf("agent: disk scan started (%s)", reason)
			}
			next.DiskScanStarted = at // also after a failure: tried again in 24 h, not every poll
		}
	}
	if next.DiskScanSent != st.DiskScanSent || next.DiskScanStarted != st.DiskScanStarted {
		if err := saveState(cfg.Prefix, next); err != nil {
			cfg.Log.Printf("agent: %s: %v", StateFile, err)
			return true
		}
		*st = next
	}
	return true
}

// requestDiskScan answers a console request (a new id). next gets the id and, when started, the start time.
func requestDiskScan(cfg Config, allow bool, req *DiskScanRequest, next *State) DiskScanStatus {
	s := DiskScanStatus{ID: req.ID}
	next.DiskScanID = req.ID
	switch {
	case !diskscan.ValidID(req.ID):
		s.ID, s.Result, s.Detail = "", "refused", "disk scan id: 8-64 characters A-Z a-z 0-9 _ -"
		return s
	case !allow:
		s.Result, s.Detail = "refused", "disk scan is off on this host (answers.yaml agent.disk_scan.allow)"
		return s
	}
	_, _, trig, _ := loadDiskScanResult(cfg.Prefix)
	now := cfg.Now()
	if diskScanRunning(*next, trig, now) {
		s.Result, s.Detail = "busy", "a scan is running; its result follows"
		return s
	}
	at := stamp(*next, now)
	if err := startDiskScan(cfg.Prefix, cfg.Run, diskscan.Trigger{ID: req.ID, Reason: "request", At: at}); err != nil {
		s.Result, s.Detail = "failed", err.Error()
		return s
	}
	next.DiskScanStarted = at
	s.Result, s.Detail = "started", "handed to "+DiskScanUnit
	return s
}

// SendDiskScan posts a scan result. A 4xx answer (not 401 / 429) is a *RefusedError (e.g. 404 = an older control
// plane without the endpoint).
func (c *Client) SendDiskScan(ctx context.Context, body []byte) error {
	resp, err := c.do(ctx, http.MethodPost, "v1/diskscan", body, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode/100 == 2:
		return nil
	case resp.StatusCode/100 == 4:
		return &RefusedError{resp.StatusCode}
	default:
		return fmt.Errorf("diskscan: HTTP %d", resp.StatusCode)
	}
}
