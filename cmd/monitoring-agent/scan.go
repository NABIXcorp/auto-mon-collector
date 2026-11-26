package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
	"github.com/NABIXcorp/auto-mon-collector/internal/lockfile"
)

// scanLockWait: how long `scan` waits for a running apply / update (the unit's TimeoutStartSec is 4 min).
var scanLockWait, scanLockPoll = 2 * time.Minute, 2 * time.Second

// scanCmd (v0.32.0) is `monitoring-agent scan`, run by the unit monitoring-scan: the service scan of plan / apply /
// update again (same detection, same answers, same generator), but it writes ONLY <prefix>/inventory.json, and only
// when the services changed (else only its mtime, the scan time). No configuration, unit or answers file is touched, nothing is restarted. Only when
// answers.yaml agent.rescan.allow.
func scanCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	prefix := fs.String("prefix", "/opt/monitoring", "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	a, err := generate.LoadEffectiveAnswers(*prefix) // v0.35.0: + the control plane's settings
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return exitPlan
	}
	if a.Agent == nil || !a.Agent.Rescan.Allow {
		fmt.Fprintln(stderr, "scan: off on this host (answers.yaml agent.rescan.allow)")
		return exitPlan
	}
	// apply / update write inventory.json themselves: never at the same time as them. The agent starts a scan right
	// after an apply restarted it, while that apply still holds the lock (its start check): wait for it a while.
	lk, err := lockInstall(*prefix)
	for waited := time.Duration(0); errors.Is(err, lockfile.ErrBusy) && waited < scanLockWait; waited += scanLockPoll {
		time.Sleep(scanLockPoll)
		lk, err = lockInstall(*prefix)
	}
	if errors.Is(err, lockfile.ErrBusy) {
		fmt.Fprintf(stdout, "scan: an apply / update is still running after %s (it writes inventory.json itself): skipped\n", scanLockWait)
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return exitPlan
	}
	defer lk.Release()
	inv, err := scanInventory(a, *prefix)
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return exitPlan
	}
	changed, err := writeInventory(*prefix, inv)
	if err != nil {
		fmt.Fprintf(stderr, "scan: write %s: %v\n", generate.InventoryFile, err)
		return exitPlan
	}
	if changed {
		fmt.Fprintf(stdout, "scan: the services changed: %s written (%d bytes)\n", generate.InventoryFile, len(inv))
	} else {
		fmt.Fprintf(stdout, "scan: no change (%s content kept, scan time recorded)\n", generate.InventoryFile)
	}
	return exitOK
}

// scanInventory: inventory.json exactly as `update` would write it: the live scan, the agent inputs (installed
// allowlist template + the agent's last probe list, as update reads them; they shape the probe files, which the
// generator checks) and generate.Generate. Its output (host.yaml, probes ...) is thrown away.
func scanInventory(a generate.Answers, prefix string) ([]byte, error) {
	h, err := scan("")
	if err != nil {
		return nil, err
	}
	in := inputs{prefix: prefix}
	if t := filepath.Join(prefix, filepath.FromSlash(generate.AllowFile)); fileExists(t) {
		in.allow = t
	}
	if _, err := agentInputs(io.Discard, &h, a, in); err != nil {
		return nil, err
	}
	g, err := generate.Generate(h, a)
	if err != nil {
		return nil, err
	}
	return g.Inventory, nil
}

// writeInventory replaces <prefix>/inventory.json atomically (temp file in the prefix + rename) with mode 644, like
// apply writes it (the unit runs as root, so the owner stays root). The same bytes = the content is not touched,
// only its mtime is set to now: the mtime is the inventory's services_at = the time of the last COMPLETED scan (a
// console "scan now" is done when services_at advances, also when nothing changed). changed = new content written.
func writeInventory(prefix string, inv []byte) (changed bool, err error) {
	p := filepath.Join(prefix, generate.InventoryFile)
	if have, err := os.ReadFile(p); err == nil && bytes.Equal(have, inv) {
		now := time.Now()
		return false, os.Chtimes(p, now, now)
	}
	tmp, err := os.CreateTemp(prefix, ".inventory-*")
	if err != nil {
		return false, err
	}
	_, err = tmp.Write(inv)
	if serr := tmp.Sync(); err == nil {
		err = serr
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o644)
	}
	if err == nil {
		err = os.Rename(tmp.Name(), p)
	}
	if err != nil {
		os.Remove(tmp.Name())
		return false, err
	}
	return true, nil
}
