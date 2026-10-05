// Command amc (auto-mon-collector) scans a Linux host, proposes what to monitor, generates the configuration
// for the official OpenTelemetry Collector (otelcol-contrib) and installs it on request. See docs/design.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/NABIXcorp/auto-mon-collector/internal/engine"
	"github.com/NABIXcorp/auto-mon-collector/internal/hostdir"
	"github.com/NABIXcorp/auto-mon-collector/internal/sysexec"
	"github.com/NABIXcorp/auto-mon-collector/internal/version"
)

const usage = `auto-mon-collector (amc): host discovery installer for otelcol-contrib

Usage:
  amc plan  --host-dir DIR [flags]          check mode: diff + validate, changes nothing (default command)
  amc apply --host-dir DIR [--start] [flags] install (backup first), optionally (re)start the collector
  amc version

Flags (plan / apply):
  --host-dir DIR   host.yaml, host.env, optional site.d/*.yaml (phase 2; detection replaces it later)
  --prefix DIR     install root (default /opt/monitoring)
  --user NAME      collector user (default otelcol-contrib)
  --no-fetch       do not download the pinned collector when it is missing or another version
  --start          (apply) restart the units and check them

Not yet available: detect, sql, uninstall, interactive questions (see docs/design.md, section 14).
`

// Exit codes (docs/design.md, section 8).
const (
	exitOK    = 0
	exitPlan  = 1
	exitUsage = 2
)

// runEngine is replaced in tests.
var runEngine = engine.Run

func run(args []string, stdout, stderr io.Writer) int {
	cmd := "plan"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version.String())
		return exitOK
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return exitOK
	case "plan", "apply":
		return planApply(cmd == "apply", args, stdout, stderr)
	case "detect", "sql", "uninstall":
		fmt.Fprintf(stderr, "amc %s: not implemented yet (see docs/design.md, section 14)\n", cmd)
		return exitPlan
	default:
		fmt.Fprintf(stderr, "amc: unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}
}

func planApply(apply bool, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("amc", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hostDir := fs.String("host-dir", "", "")
	prefix := fs.String("prefix", "/opt/monitoring", "")
	user := fs.String("user", "otelcol-contrib", "")
	noFetch := fs.Bool("no-fetch", false, "")
	start := fs.Bool("start", false, "")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *hostDir == "" {
		fmt.Fprintln(stderr, "amc: --host-dir is required (detection comes in a later version)")
		return exitUsage
	}
	if *start && !apply {
		fmt.Fprintln(stderr, "amc: --start only works with apply")
		return exitUsage
	}
	d, err := hostdir.Load(*hostDir)
	if err != nil {
		fmt.Fprintf(stderr, "amc: %v\n", err)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	res, err := runEngine(ctx, engine.Options{
		Prefix: *prefix, User: *user, Apply: apply, Start: *start, Fetch: !*noFetch,
		Out: stdout, Runner: sysexec.Runner{},
	}, d)
	if err != nil {
		fmt.Fprintf(stderr, "amc: %v\n", err)
		if errors.Is(err, context.Canceled) {
			return exitPlan
		}
		return exitUsage
	}
	if res.Failures > 0 {
		return exitPlan
	}
	return exitOK
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
