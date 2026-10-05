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
  amc uninstall [--yes] [--purge-data] [--purge-secrets] [--purge]   check mode unless --yes
  amc version

Flags (plan / apply):
  --host-dir DIR   host.yaml, host.env, optional site.d/*.yaml (phase 2; detection replaces it later)
  --prefix DIR     install root (default /opt/monitoring)
  --user NAME      collector user (default otelcol-contrib)
  --no-fetch       do not download the pinned collector when it is missing or another version
  --no-smoke       skip the 25 s test run of the new config (local sink, nothing sent to the backend)
  --no-rollback    (apply --start) keep the new state even when a unit does not start
  --start          (apply) restart the units and check them

Flags (uninstall): removes units, files and what amc recorded in <prefix>/amc-state.json (ACLs, groups,
SELinux rules). Kept unless asked: data/ + backup/ (--purge-data), secrets/ (--purge-secrets: you type
"yes"; without a terminal --yes counts), the collector user (--purge, only if amc created it).

Not yet available: detect, sql, interactive questions (see docs/design.md, section 14).
`

// Exit codes (docs/design.md, section 8).
const (
	exitOK    = 0
	exitPlan  = 1
	exitUsage = 2
)

// replaced in tests
var (
	runEngine    = engine.Run
	runUninstall = engine.Uninstall
	confirm      = confirmTTY
)

// confirmTTY asks on the terminal; ok=false when there is no terminal.
func confirmTTY(question string) (answer string, ok bool) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", false
	}
	defer tty.Close()
	fmt.Fprint(tty, question)
	var s string
	fmt.Fscanln(tty, &s)
	return s, true
}

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
	case "uninstall":
		return uninstall(args, stdout, stderr)
	case "detect", "sql":
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
	noSmoke := fs.Bool("no-smoke", false, "")
	noRollback := fs.Bool("no-rollback", false, "")
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
		Prefix: *prefix, User: *user, Apply: apply, Start: *start, Fetch: !*noFetch, Smoke: !*noSmoke,
		Rollback: !*noRollback,
		Out:      stdout, Runner: sysexec.Runner{},
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

func uninstall(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("amc uninstall", flag.ContinueOnError)
	fs.SetOutput(stderr)
	prefix := fs.String("prefix", "/opt/monitoring", "")
	user := fs.String("user", "otelcol-contrib", "")
	yes := fs.Bool("yes", false, "")
	purgeData := fs.Bool("purge-data", false, "")
	purgeSecrets := fs.Bool("purge-secrets", false, "")
	purgeUser := fs.Bool("purge", false, "")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	// Secrets cannot be recreated by amc: a typed "yes" on the terminal; in automation (no terminal) the
	// two explicit flags --purge-secrets --yes are the confirmation.
	if *purgeSecrets && *yes {
		if answer, isTTY := confirm("Delete " + *prefix + "/secrets (backend + database credentials)? Type yes: "); isTTY && answer != "yes" {
			fmt.Fprintln(stderr, "amc: secrets kept (answer was not yes); nothing removed")
			return exitPlan
		}
	}
	res, err := runUninstall(engine.Options{
		Prefix: *prefix, User: *user, Apply: *yes, Out: stdout, Runner: sysexec.Runner{},
	}, engine.UninstallOptions{PurgeData: *purgeData, PurgeSecrets: *purgeSecrets, PurgeUser: *purgeUser})
	if err != nil {
		fmt.Fprintf(stderr, "amc: %v\n", err)
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
