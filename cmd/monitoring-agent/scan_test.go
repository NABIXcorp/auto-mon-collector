package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/detect"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

const scanTestKey = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// scanPrefix: an installed prefix with an agent section (+ extra answers lines) and a fake host.
func scanPrefix(t *testing.T, extra string, host detect.Source) string {
	t.Helper()
	pre := t.TempDir()
	ans := "agent:\n  url: https://agent.example.com/agent/\n  control_plane_key: \"" + scanTestKey + "\"\n" + extra
	if err := os.WriteFile(filepath.Join(pre, "answers.yaml"), []byte(ans), 0o644); err != nil {
		t.Fatal(err)
	}
	old := detectSource
	detectSource = host
	t.Cleanup(func() { detectSource = old })
	return pre
}

func memHost(procs map[string]string) detect.Mem {
	m := detect.Mem{Files: map[string]string{"/etc/os-release": "PRETTY_NAME=\"Test Linux 9\"\n"}}
	for pid, comm := range procs {
		m.Files["/proc/"+pid+"/comm"] = comm + "\n"
		m.Files["/proc/"+pid+"/cmdline"] = "/usr/bin/" + comm + "\x00"
	}
	return m
}

func inventoryIDs(t *testing.T, pre string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pre, generate.InventoryFile))
	if err != nil {
		t.Fatal(err)
	}
	var doc generate.InventoryDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, s := range doc.Services {
		ids = append(ids, s.ID)
	}
	return ids
}

// v0.32.0: `scan` writes inventory.json as update would (a new service shows), keeps the content of an unchanged
// file but records the scan time in its mtime (services_at), and touches nothing else in the prefix.
func TestScanWritesOnlyTheInventory(t *testing.T) {
	pre := scanPrefix(t, "  rescan:\n    allow: true\n", memHost(map[string]string{"10": "nginx"}))
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--prefix", pre}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	if ids := inventoryIDs(t, pre); strings.Join(ids, ",") != "nginx" {
		t.Fatalf("services %v", ids)
	}
	p := filepath.Join(pre, generate.InventoryFile)
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	// the same host: the content stays, but the mtime (= services_at) is the time of this scan, so a console
	// "scan now" sees services_at advance also when nothing changed
	before, _ := os.ReadFile(p)
	out.Reset()
	start := time.Now().Truncate(time.Second)
	if code := run([]string{"scan", "--prefix", pre}, &out, &errb); code != exitOK || !strings.Contains(out.String(), "no change") {
		t.Fatalf("second scan: %d %s %s", code, out.String(), errb.String())
	}
	if fi, _ := os.Stat(p); fi.ModTime().Before(start) {
		t.Errorf("unchanged scan did not record its time: mtime %v, scan at %v", fi.ModTime(), start)
	}
	if after, _ := os.ReadFile(p); !bytes.Equal(before, after) {
		t.Errorf("unchanged inventory content rewritten:\n%s\n%s", before, after)
	}
	// a service installed later: written
	detectSource = memHost(map[string]string{"10": "nginx", "20": "dockerd"})
	out.Reset()
	if code := run([]string{"scan", "--prefix", pre}, &out, &errb); code != exitOK || !strings.Contains(out.String(), "the services changed") {
		t.Fatalf("third scan: %d %s %s", code, out.String(), errb.String())
	}
	if ids := inventoryIDs(t, pre); strings.Join(ids, ",") != "docker,nginx" {
		t.Errorf("services %v", ids)
	}
	ents, _ := os.ReadDir(pre)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if got := strings.Join(names, ","); got != ".monitoring.lock,answers.yaml,inventory.json" {
		t.Errorf("prefix after scans: %s (only inventory.json may be written, no temp files left)", got)
	}
}

// v0.32.0: without agent.rescan.allow (or without an agent) `scan` refuses and writes nothing.
func TestScanOff(t *testing.T) {
	for name, extra := range map[string]string{"no switch": "", "switch off": "  rescan:\n    allow: false\n"} {
		pre := scanPrefix(t, extra, memHost(map[string]string{"10": "nginx"}))
		var out, errb bytes.Buffer
		if code := run([]string{"scan", "--prefix", pre}, &out, &errb); code != exitPlan || !strings.Contains(errb.String(), "agent.rescan.allow") {
			t.Errorf("%s: exit %d %s", name, code, errb.String())
		}
		if _, err := os.Stat(filepath.Join(pre, generate.InventoryFile)); err == nil {
			t.Errorf("%s: inventory written", name)
		}
	}
}
