package main

// install (v0.24.0): one command for a new host. The console hands out a one-time token and this line:
//
//	curl -fsSL https://<console>/install.sh | sudo bash -s -- --token-stdin   (install.sh runs: install --console ...)
//
// Steps: token from stdin -> POST <console>v1/bootstrap (project, host name, agent block, allowlist template,
// OTLP gateway endpoint + this host's gateway token, release mirror) -> answers.yaml + secrets/collector.env from
// the bundle -> plan (diff, validate, smoke run) -> "Apply? [y/N]" (or --yes) -> apply --start (backup, rollback)
// -> agent enrol with the same token (now used up). Nothing of the bundle's secrets is printed.

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/engine"
	"github.com/NABIXcorp/auto-mon-collector/internal/sysexec"
)

// replaced in tests
var (
	installNeedRoot = true
	installConfirm  = confirmTTY
)

func installCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("monitoring-agent install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	console := fs.String("console", "", "")
	tokenStdin := fs.Bool("token-stdin", false, "")
	host := fs.String("host", "", "")
	yes := fs.Bool("yes", false, "")
	prefix := fs.String("prefix", "/opt/monitoring", "")
	detectFile := fs.String("detect-json", "", "")
	collectorFile := fs.String("collector-file", "", "")
	noSmoke := fs.Bool("no-smoke", false, "")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return exitUsage
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "monitoring-agent install: "+format+"\n", a...)
		return exitUsage
	}
	if !*tokenStdin {
		return fail("give the one-time token on stdin with --token-stdin (never as an argument)")
	}
	if err := agent.ConsoleURL(*console); err != nil {
		return fail("%v", err)
	}
	if installNeedRoot && os.Geteuid() != 0 {
		return fail("run as root (sudo)")
	}
	for _, f := range []string{"answers.yaml", "secrets/collector.env"} {
		if fileExists(filepath.Join(*prefix, filepath.FromSlash(f))) {
			return fail("%s exists: this host is installed already (use `monitoring-agent update`, or uninstall first)", filepath.Join(*prefix, f))
		}
	}
	tok, _ := bufio.NewReader(agentStdin).ReadString('\n')
	tok = strings.TrimSpace(tok)
	if tok == "" || len(tok) > 512 {
		return fail("no token on stdin")
	}
	name := *host
	if name == "" {
		h, err := os.Hostname()
		if err != nil {
			return fail("host name: %v (give --host NAME)", err)
		}
		name = h
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	b, err := agent.Bootstrap(ctx, *console, name, tok, nil)
	if err != nil {
		return fail("%v", err)
	}
	a := b.Answers()
	if err := a.Validate(); err != nil {
		return fail("the console's answers: %v", err)
	}
	fmt.Fprintf(stdout, "console: project %s, host %s; data -> %s (gateway token, not shown)\n", b.Project, b.HostName, b.OTLP.Endpoint)
	fmt.Fprintf(stdout, "console: remote updates %s, collector overlays %s, release mirror %s\n",
		onOff(b.Agent.UpdateAllow), onOff(b.Agent.SiteAllow), orGitHub(b.ReleaseMirror))

	tmp, err := os.MkdirTemp("", "monitoring-install-")
	if err != nil {
		return fail("%v", err)
	}
	defer os.RemoveAll(tmp)
	allow := ""
	if strings.TrimSpace(b.Allow) != "" {
		allow = filepath.Join(tmp, "agent-allow.yaml")
		if err := os.WriteFile(allow, []byte(b.Allow), 0o600); err != nil {
			return fail("%v", err)
		}
	}
	d, err := desiredFrom(stdout, a, *detectFile, "", inputs{prefix: *prefix, allow: allow, keepCP: true})
	if err != nil {
		return fail("%v", err)
	}
	src, cleanup := collectorSource()
	defer cleanup()
	opts := engine.Options{
		Prefix: *prefix, User: engine.DefaultUser, Fetch: true, Smoke: !*noSmoke, Rollback: true,
		SecretsInput: b.Secrets(), Collector: src, CollectorFile: *collectorFile, Out: stdout, Runner: sysexec.Runner{},
	}
	res, err := runEngine(ctx, opts, d)
	if err != nil {
		return fail("%v", err)
	}
	if res.Failures > 0 {
		fmt.Fprintln(stderr, "monitoring-agent install: the plan has failures: nothing was installed")
		return exitPlan
	}
	if !*yes {
		ans, ok := installConfirm("\nApply? (backup first, start, automatic rollback if it does not start) [y/N] ")
		if !ok {
			return fail("no terminal to ask: add --yes to apply")
		}
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
			fmt.Fprintln(stdout, "nothing installed")
			return exitPlan
		}
	}
	lk, err := lockInstall(*prefix)
	if err != nil {
		return fail("%v", err)
	}
	opts.Apply, opts.Start, opts.Smoke = true, true, false // the identical config passed the smoke run above
	res, err = runEngine(ctx, opts, d)
	if lk != nil {
		lk.Release()
	}
	if err != nil {
		return fail("%v", err)
	}
	if res.Failures > 0 {
		return exitPlan
	}

	uid, gid := -1, -1
	if installNeedRoot {
		u, err := user.Lookup(engine.AgentUser)
		if err != nil {
			return fail("user %s missing after apply: %v", engine.AgentUser, err)
		}
		uid, _ = strconv.Atoi(u.Uid)
		gid, _ = strconv.Atoi(u.Gid)
	}
	if err := agent.Enrol(ctx, *prefix, "", tok, uid, gid, nil); err != nil {
		if errors.Is(err, context.Canceled) {
			return exitPlan
		}
		fmt.Fprintf(stderr, "monitoring-agent install: installed, but the enrolment failed: %v\n"+
			"  ask the console for a new token, then: sudo %s agent enrol --token-stdin\n", err, filepath.Join(*prefix, "bin", "monitoring-agent"))
		return exitPlan
	}
	fmt.Fprintf(stdout, "\ninstalled and enrolled as %s (project %s); the host shows in the console within a minute\n", b.HostName, b.Project)
	return exitOK
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func orGitHub(m string) string {
	if m == "" {
		return "none (GitHub)"
	}
	return m
}
