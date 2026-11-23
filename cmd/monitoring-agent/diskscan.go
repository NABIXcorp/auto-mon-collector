package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/diskscan"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

// diskScanTimeout: the walk stops here (the unit's TimeoutStartSec is 11 min); what was found is kept, marked partial.
var diskScanTimeout = 10 * time.Minute

// diskScanCmd (v0.29.0) is `monitoring-agent disk-scan`, run by the unit monitoring-diskscan: walk the local disks,
// write <prefix>/agent/diskscan/result.json for the agent to upload. Only when answers.yaml agent.disk_scan.allow.
func diskScanCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("disk-scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	prefix := fs.String("prefix", "/opt/monitoring", "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	a, err := generate.LoadAnswers(filepath.Join(*prefix, "answers.yaml"))
	if err != nil {
		fmt.Fprintf(stderr, "disk-scan: %v\n", err)
		return exitPlan
	}
	if a.Agent == nil || !a.Agent.DiskScan.Allow {
		fmt.Fprintln(stderr, "disk-scan: off on this host (answers.yaml agent.disk_scan.allow)")
		return exitPlan
	}
	ctx, cancel := context.WithTimeout(context.Background(), diskScanTimeout)
	defer cancel()
	r := diskscan.Scan(ctx, diskscan.Options{Exclude: a.Agent.DiskScan.Exclude, Trigger: diskscan.LoadTrigger(*prefix)})
	if err := diskscan.Write(*prefix, r); err != nil {
		fmt.Fprintf(stderr, "disk-scan: write the result: %v\n", err)
		return exitPlan
	}
	for _, m := range r.Mounts {
		note := ""
		if m.Partial {
			note = " (time limit: partial)"
		}
		fmt.Fprintf(stdout, "disk-scan: %s %s: %d files, %d folders, %d unreadable%s\n", m.Mount, m.FS, m.Files, m.Dirs, m.Errors, note)
	}
	if r.Error != "" {
		fmt.Fprintf(stderr, "disk-scan: %s\n", r.Error)
		return exitPlan
	}
	fmt.Fprintf(stdout, "disk-scan: %s scan done in %d s\n", r.Reason, r.Finished-r.Started)
	return exitOK
}
