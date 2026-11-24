package agent

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// v0.32.0: the schedule with a clock: started at the first tick after the agent start, not again within 15 min,
// again after 15 min; a request inside the 5 min after a start is busy, after it started; a failed start waits
// 15 min. A state from before this agent process (an old start) does not delay the first scan.
func TestRescanSchedule(t *testing.T) {
	pre := t.TempDir()
	if err := os.MkdirAll(filepath.Join(pre, "agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	f := &fakeRun{}
	cfg := Config{Prefix: pre, Run: f.run, Now: func() time.Time { return now }, Log: log.New(io.Discard, "", 0)}
	starts := func() int { return len(f.calls) }
	// a start 10 min before this process began (the previous agent, < 15 min ago): started again now
	st := State{RescanStarted: now.Add(-10 * time.Minute).UnixMilli()}
	boot := now
	rescanTick(cfg, true, boot, &st)
	if starts() != 1 || st.RescanStarted != now.UnixMilli() {
		t.Fatalf("first tick: %d starts, %+v", starts(), st)
	}
	if saved, err := LoadState(pre); err != nil || saved.RescanStarted != st.RescanStarted {
		t.Fatalf("state not saved: %+v %v", saved, err)
	}
	for _, d := range []time.Duration{time.Minute, 6 * time.Minute, 14 * time.Minute} {
		now = boot.Add(d)
		rescanTick(cfg, true, boot, &st)
	}
	if starts() != 1 {
		t.Fatalf("started again within 15 min: %d", starts())
	}
	// request 3 min after the start: busy; 6 min after: started
	next := st
	now = boot.Add(3 * time.Minute)
	if s := requestRescan(cfg, true, &RescanRequest{ID: "rescan-aaaaaaaa"}, &next); s.Result != "busy" {
		t.Fatalf("request while running: %+v", s)
	}
	now = boot.Add(14 * time.Minute)
	if s := requestRescan(cfg, true, &RescanRequest{ID: "rescan-bbbbbbbb"}, &next); s.Result != "started" || next.RescanStarted != now.UnixMilli() {
		t.Fatalf("request after the busy time: %+v %+v", s, next)
	}
	st = next
	// periodic: 15 min after the LAST start (the request's)
	now = boot.Add(28 * time.Minute)
	rescanTick(cfg, true, boot, &st)
	if starts() != 2 {
		t.Fatalf("started before 15 min after the request: %d", starts())
	}
	now = boot.Add(29 * time.Minute)
	rescanTick(cfg, true, boot, &st)
	if starts() != 3 {
		t.Fatalf("no periodic start: %d", starts())
	}
	// switched off: nothing
	now = boot.Add(2 * time.Hour)
	rescanTick(cfg, false, boot, &st)
	if starts() != 3 {
		t.Fatalf("started while off: %d", starts())
	}
	if s := requestRescan(cfg, false, &RescanRequest{ID: "rescan-cccccccc"}, &next); s.Result != "refused" {
		t.Fatalf("request while off: %+v", s)
	}
}

// v0.32.0: a failed automatic start is recorded as RescanFailed (not started) and retried after 15 min.
func TestRescanFailedRetry(t *testing.T) {
	pre := t.TempDir()
	if err := os.MkdirAll(filepath.Join(pre, "agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	fail := true
	var calls int
	run := func(name string, args ...string) ([]byte, error) {
		calls++
		if fail {
			return []byte("Unit monitoring-scan.service not found."), os.ErrNotExist
		}
		return nil, nil
	}
	cfg := Config{Prefix: pre, Run: run, Now: func() time.Time { return now }, Log: log.New(io.Discard, "", 0)}
	boot := now
	var st State
	rescanTick(cfg, true, boot, &st)
	if calls != 1 || st.RescanStarted != 0 || st.RescanFailed != now.UnixMilli() {
		t.Fatalf("failed start: %d %+v", calls, st)
	}
	now = boot.Add(10 * time.Minute)
	rescanTick(cfg, true, boot, &st)
	if calls != 1 {
		t.Fatalf("retried before 15 min: %d", calls)
	}
	fail = false
	now = boot.Add(15 * time.Minute)
	rescanTick(cfg, true, boot, &st)
	if calls != 2 || st.RescanStarted != now.UnixMilli() {
		t.Fatalf("no retry after 15 min: %d %+v", calls, st)
	}
}

// v0.32.0: a started scan is "running" until inventory.json has an mtime at or after its start (every completed
// scan sets it), at most rescanBusy.
func TestRescanRunningEndsWithTheScan(t *testing.T) {
	pre := t.TempDir()
	start := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	st := State{RescanStarted: start.UnixMilli()}
	p := filepath.Join(pre, "inventory.json")
	if !rescanRunning(pre, st, start.Add(time.Minute)) {
		t.Fatal("no file, 1 min after the start: not running")
	}
	if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := start.Add(-time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	if !rescanRunning(pre, st, start.Add(time.Minute)) {
		t.Fatal("an older inventory.json ended the scan")
	}
	fin := start.Add(3 * time.Second)
	if err := os.Chtimes(p, fin, fin); err != nil {
		t.Fatal(err)
	}
	if rescanRunning(pre, st, start.Add(time.Minute)) {
		t.Fatal("finished scan (mtime after the start) still running")
	}
	if rescanRunning(t.TempDir(), st, start.Add(rescanBusy)) {
		t.Fatal("running after rescanBusy")
	}
}
