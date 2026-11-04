package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/NABIXcorp/auto-mon-collector/internal/lockfile"
	"github.com/NABIXcorp/auto-mon-collector/internal/selfupdate"
	"github.com/NABIXcorp/auto-mon-collector/internal/version"
)

// replaced in tests
var (
	runSelfUpdate = selfupdate.Run
	geteuid       = os.Geteuid
)

// selfUpdateCmd: `monitoring-agent self-update --request FILE` (v0.16.0), run as root by the unit monitoring-update, which the
// agent starts after a signed update request. Everything is checked again here (internal/selfupdate).
func selfUpdateCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("monitoring-agent self-update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	prefix := fs.String("prefix", "/opt/monitoring", "")
	request := fs.String("request", "", "")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return exitUsage
	}
	if *request == "" {
		fmt.Fprintln(stderr, "monitoring-agent self-update: --request FILE is required (the signed request the agent saved)")
		return exitUsage
	}
	if geteuid() != 0 {
		fmt.Fprintln(stderr, "monitoring-agent self-update: run as root (the unit monitoring-update does)")
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	res := runSelfUpdate(ctx, selfupdate.Options{Prefix: *prefix, Request: *request, Running: version.Version, Out: stdout})
	if res.Result != "ok" {
		return exitPlan
	}
	return exitOK
}

// lockInstall (v0.16.0): apply / update hold <prefix>/.monitoring.lock, so they never run at the same time as each other
// or as a self-update. No prefix yet (first install) = nothing to lock against.
func lockInstall(prefix string) (*lockfile.Lock, error) {
	if _, err := os.Stat(prefix); err != nil {
		return nil, nil
	}
	return lockfile.Acquire(prefix)
}
