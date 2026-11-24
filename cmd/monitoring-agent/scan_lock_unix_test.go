//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
	"github.com/NABIXcorp/auto-mon-collector/internal/lockfile"
)

// v0.32.0: `scan` waits for a running apply / update (the lock); still held after scanLockWait = skipped, nothing
// written; released in time = the scan runs.
func TestScanWaitsForTheLock(t *testing.T) {
	pre := scanPrefix(t, "  rescan:\n    allow: true\n", memHost(map[string]string{"10": "nginx"}))
	oldWait, oldPoll := scanLockWait, scanLockPoll
	scanLockWait, scanLockPoll = 300*time.Millisecond, 50*time.Millisecond
	defer func() { scanLockWait, scanLockPoll = oldWait, oldPoll }()
	l, err := lockfile.Acquire(pre)
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--prefix", pre}, &out, &errb); code != exitOK || !strings.Contains(out.String(), "skipped") {
		t.Fatalf("held lock: exit %d %s %s", code, out.String(), errb.String())
	}
	if _, err := os.Stat(filepath.Join(pre, generate.InventoryFile)); err == nil {
		t.Fatal("inventory written while the lock was held")
	}
	scanLockWait = 5 * time.Second
	go func() { time.Sleep(200 * time.Millisecond); l.Release() }()
	out.Reset()
	if code := run([]string{"scan", "--prefix", pre}, &out, &errb); code != exitOK || !strings.Contains(out.String(), "the services changed") {
		t.Fatalf("lock released: exit %d %s %s", code, out.String(), errb.String())
	}
}
