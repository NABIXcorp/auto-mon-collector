package agent_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/diskscan"
)

const scanCmd = "systemctl start --no-block monitoring-diskscan.service"

func waitCount(t *testing.T, what string, f func() int, n int) {
	t.Helper()
	for i := 0; i < 250; i++ {
		if f() >= n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: %d, want %d", what, f(), n)
}

func TestDiskScanDailyUploadAndRequest(t *testing.T) {
	cp, pre, f := startAgent(t, "  disk_scan:\n    allow: true\n", "v0.29.0")
	// first poll: never scanned -> a daily scan is started (trigger written first)
	waitCount(t, "daily start", func() int { return f.count(scanCmd) }, 1)
	if tr := diskscan.LoadTrigger(pre); tr.Reason != "daily" || tr.ID != "" {
		t.Fatalf("trigger %+v", tr)
	}
	// the unit's result appears: uploaded once
	tr := diskscan.LoadTrigger(pre)
	res := diskscan.Result{Version: 1, Reason: "daily", TriggerAt: tr.At, Started: time.Now().Unix(), Finished: time.Now().Unix() + 1, Mounts: []diskscan.Mount{}}
	if err := diskscan.Write(pre, res); err != nil {
		t.Fatal(err)
	}
	waitCount(t, "upload", func() int { return len(cp.DiskScans()) }, 1)
	var got diskscan.Result
	if err := json.Unmarshal(cp.DiskScans()[0], &got); err != nil || got.Finished != res.Finished {
		t.Fatalf("uploaded %v %s", err, cp.DiskScans()[0])
	}
	// a console request: started at once (the daily scan has its result), the id goes into the trigger
	cp.PublishDiskScan("app-1", dbProbe, "scan-0123456789")
	s := waitStatuses(t, cp, 1)[0]
	if s.DiskScan == nil || s.DiskScan.Result != "started" || s.DiskScan.ID != "scan-0123456789" {
		t.Fatalf("status %+v %+v", s, s.DiskScan)
	}
	if tr := diskscan.LoadTrigger(pre); tr.Reason != "request" || tr.ID != "scan-0123456789" {
		t.Fatalf("trigger %+v", tr)
	}
	// the same id again: not started again; a new id while that scan runs: busy
	cp.PublishDiskScan("app-1", dbProbe, "scan-0123456789")
	if s := waitStatuses(t, cp, 2)[1]; s.DiskScan != nil {
		t.Fatalf("repeated id answered again: %+v", s.DiskScan)
	}
	cp.PublishDiskScan("app-1", dbProbe, "scan-abcdefghij")
	if s := waitStatuses(t, cp, 3)[2]; s.DiskScan == nil || s.DiskScan.Result != "busy" {
		t.Fatalf("second request while running: %+v", s.DiskScan)
	}
	time.Sleep(500 * time.Millisecond) // several polls: no second upload, no second daily start
	if n := len(cp.DiskScans()); n != 1 {
		t.Errorf("uploads: %d", n)
	}
	if n := f.count(scanCmd); n != 2 {
		t.Errorf("unit starts: %d (daily + request)", n)
	}
	invs, _ := cp.Inventories()
	if len(invs) == 0 || !invs[len(invs)-1].DiskScan {
		t.Errorf("inventory: disk_scan not true: %+v", invs)
	}
}

func TestDiskScanOff(t *testing.T) {
	cp, pre, f := startAgent(t, "", "v0.29.0")
	cp.PublishDiskScan("app-1", dbProbe, "scan-0123456789")
	s := waitStatuses(t, cp, 1)[0]
	if s.DiskScan == nil || s.DiskScan.Result != "refused" {
		t.Fatalf("status %+v", s.DiskScan)
	}
	// a result file left from before is not uploaded either
	if err := os.WriteFile(filepath.Join(pre, filepath.FromSlash(diskscan.ResultFile)), []byte(fmt.Sprintf(`{"finished_at":%d}`, time.Now().Unix())), 0o600); err != nil {
		if err := os.MkdirAll(filepath.Join(pre, "agent", "diskscan"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(500 * time.Millisecond)
	if f.count(scanCmd) != 0 || len(cp.DiskScans()) != 0 {
		t.Fatalf("disk scan off, but: starts %d, uploads %d", f.count(scanCmd), len(cp.DiskScans()))
	}
	invs, _ := cp.Inventories()
	if len(invs) == 0 || invs[0].DiskScan {
		t.Errorf("inventory: disk_scan: %+v", invs)
	}
}
