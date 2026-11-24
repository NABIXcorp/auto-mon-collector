package agent_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

const rescanCmd = "systemctl start --no-block monitoring-scan.service"

// v0.32.0: with agent.rescan.allow the first poll starts the scan unit once (not again every poll), the inventory
// reports rescan_allowed and services_at (the mtime of inventory.json), a request while the scan runs is "busy",
// a repeated id is not answered twice, a request after the scan finished (mtime >= its start) starts a new one.
func TestRescanStartAndRequest(t *testing.T) {
	cp, pre, f := startAgent(t, "  rescan:\n    allow: true\n", "v0.32.0")
	waitCount(t, "start after the agent start", func() int { return f.count(rescanCmd) }, 1)
	// the scan writes inventory.json: the next inventory carries it and its time
	at := time.Now().Add(-time.Minute).Truncate(time.Second)
	p := filepath.Join(pre, generate.InventoryFile)
	if err := os.WriteFile(p, []byte(`{"schema":1,"services":[{"id":"nginx","monitored":false}],"listen":[]}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, at, at); err != nil {
		t.Fatal(err)
	}
	waitCount(t, "inventory with services_at", func() int {
		invs, _ := cp.Inventories()
		if len(invs) > 0 && invs[len(invs)-1].ServicesAt == at.Unix() {
			return 1
		}
		return 0
	}, 1)
	invs, _ := cp.Inventories()
	if last := invs[len(invs)-1]; !last.RescanAllowed || string(last.Services) == "null" {
		t.Errorf("inventory: %+v", last)
	}
	// a request right after the automatic start: busy (that scan's inventory answers it)
	cp.PublishRescan("app-1", dbProbe, "rescan-0123456789")
	s := waitStatuses(t, cp, 1)[0]
	if s.Rescan == nil || s.Rescan.Result != "busy" || s.Rescan.ID != "rescan-0123456789" {
		t.Fatalf("status %+v %+v", s, s.Rescan)
	}
	cp.PublishRescan("app-1", dbProbe, "rescan-0123456789")
	if s := waitStatuses(t, cp, 2)[1]; s.Rescan != nil {
		t.Fatalf("repeated id answered again: %+v", s.Rescan)
	}
	// a bad id: refused without an id
	cp.PublishRescan("app-1", dbProbe, "bad id")
	if s := waitStatuses(t, cp, 3)[2]; s.Rescan == nil || s.Rescan.Result != "refused" || s.Rescan.ID != "" {
		t.Fatalf("bad id: %+v", s.Rescan)
	}
	time.Sleep(500 * time.Millisecond) // several polls: no second automatic start within 15 min
	if n := f.count(rescanCmd); n != 1 {
		t.Errorf("unit starts: %d, want 1", n)
	}
	// the scan finished (it sets the mtime of inventory.json, also without a change): a new request starts a new
	// scan at once (a "busy" would never bring the newer services_at the console waits for), and services_at advances
	done := time.Now().Add(time.Second)
	if err := os.Chtimes(p, done, done); err != nil {
		t.Fatal(err)
	}
	cp.PublishRescan("app-1", dbProbe, "rescan-abcdefghij")
	if s := waitStatuses(t, cp, 4)[3]; s.Rescan == nil || s.Rescan.Result != "started" {
		t.Fatalf("request after the scan finished: %+v", s.Rescan)
	}
	if n := f.count(rescanCmd); n != 2 {
		t.Errorf("unit starts: %d, want 2", n)
	}
	waitCount(t, "inventory with the newer services_at", func() int {
		invs, _ := cp.Inventories()
		if len(invs) > 0 && invs[len(invs)-1].ServicesAt == done.Unix() {
			return 1
		}
		return 0
	}, 1)
}

// v0.32.0: switched off: no start, a request is refused, the inventory says rescan_allowed false.
func TestRescanOff(t *testing.T) {
	cp, _, f := startAgent(t, "", "v0.32.0")
	cp.PublishRescan("app-1", dbProbe, "rescan-0123456789")
	s := waitStatuses(t, cp, 1)[0]
	if s.Rescan == nil || s.Rescan.Result != "refused" {
		t.Fatalf("status %+v", s.Rescan)
	}
	time.Sleep(500 * time.Millisecond)
	if n := f.count(rescanCmd); n != 0 {
		t.Fatalf("rescan off, but %d starts", n)
	}
	invs, _ := cp.Inventories()
	if len(invs) == 0 || invs[0].RescanAllowed || invs[0].ServicesAt != 0 {
		t.Errorf("inventory: %+v", invs)
	}
}

// v0.32.0 (like the disk scan's v0.31.1 fix): a start that fails (the unit not linked yet) is not a running scan: a
// console request right after it starts the scan instead of answering "busy", and the automatic start is not
// repeated every poll.
func TestRescanFailedStartIsNotBusy(t *testing.T) {
	f := &lockedRun{fail: rescanCmd}
	cp, _, _ := startAgentRun(t, "  rescan:\n    allow: true\n", "v0.32.0", f)
	waitCount(t, "first try", func() int { return f.count(rescanCmd) }, 1)
	time.Sleep(500 * time.Millisecond)
	if n := f.count(rescanCmd); n != 1 {
		t.Fatalf("tries after a failed start: %d, want 1", n)
	}
	// still failing: the request says failed
	cp.PublishRescan("app-1", dbProbe, "rescan-0000000001")
	if s := waitStatuses(t, cp, 1)[0]; s.Rescan == nil || s.Rescan.Result != "failed" {
		t.Fatalf("request while the unit cannot start: %+v", s.Rescan)
	}
	f.setFail("")
	cp.PublishRescan("app-1", dbProbe, "rescan-0000000002")
	if s := waitStatuses(t, cp, 2)[1]; s.Rescan == nil || s.Rescan.Result != "started" {
		t.Fatalf("request after a failed start: %+v", s.Rescan)
	}
}
