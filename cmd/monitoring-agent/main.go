// Command monitoring-agent (repository auto-mon-collector) scans a Linux host, proposes what to monitor, generates the configuration
// for monitoring-collector (our OpenTelemetry Collector build, same signed release) and installs it on request.
// See docs/design.md.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/ask"
	"github.com/NABIXcorp/auto-mon-collector/internal/collector"
	"github.com/NABIXcorp/auto-mon-collector/internal/detect"
	"github.com/NABIXcorp/auto-mon-collector/internal/engine"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
	"github.com/NABIXcorp/auto-mon-collector/internal/hostdir"
	"github.com/NABIXcorp/auto-mon-collector/internal/sysexec"
	"github.com/NABIXcorp/auto-mon-collector/internal/version"
)

const usage = `monitoring-agent: host discovery installer and agent for monitoring-collector (OpenTelemetry)

Usage:
  monitoring-agent install --console URL --token-stdin [--yes] [--host NAME]
        a new host in one step: the console's settings for it (one-time token from the console), plan,
        apply + start after "yes", then enrol the agent
  monitoring-agent plan  --answers FILE [flags]
        detect + generate + diff + validate + smoke run; changes nothing
  monitoring-agent apply --answers FILE [--start] [flags]
        the same, then install (backup first), optionally (re)start
  monitoring-agent update [--plan] [flags]
        new release on an installed host, no files to copy: the saved answers + the installed site.d, plan,
        then apply + start only when something changes (--plan: stop after the plan)
  monitoring-agent generate --answers FILE [--out DIR]
        only write host.yaml + host.env (nothing installed)
  monitoring-agent detect [--json]
        read-only: which services this host runs (needs root)
  monitoring-agent agent enrol --token-stdin [--prefix DIR]
        register this host with the control plane (answers: agent:)
  monitoring-agent agent run [--prefix DIR]
        the agent daemon (started by the unit monitoring-agent)
  monitoring-agent self-update --request FILE [--prefix DIR]
        root: a signed update request saved by the agent: verify it, download + verify the signed release,
        install it, then update (run by the unit monitoring-update; answers: agent.update)
  monitoring-agent uninstall [--yes] [--purge-data] [--purge-secrets] [--purge]
        check mode unless --yes
  monitoring-agent version

Flags (plan / apply / generate):
  --answers FILE      what a scan cannot know: Oracle service name + user, HTTP checks, services on/off
  --detect-json FILE  use a saved "monitoring-agent detect --json" instead of scanning (offline / review)
  --site-dir DIR      operator overlay *.yaml, installed as config/site.d/ (plan / apply)
  --agent-allow FILE  project allowlist template for the agent, installed as config/agent-allow.yaml
                      (plan / apply; without it the installed template is kept, "--agent-allow none"
                      removes it; update keeps it)
  --host-dir DIR      instead of --answers: a prepared host part (host.yaml, host.env, site.d/)
  --prefix DIR        install root (default /opt/monitoring)
  --user NAME         collector user (default monitoring; otelcol-contrib before v0.21.0, moved by an apply)
  --no-fetch          do not download the collector of this release when it is missing or different
  --collector-file F  install F as bin/monitoring-collector instead of downloading (CI, no internet);
                      NOT checked against the release: its sha256 is printed (plan / apply / update)
  --no-smoke          skip the 25 s test run of the new config (local sink, nothing sent to the backend)
  --no-rollback       (apply --start) keep the new state even when a unit does not start
  --start             (apply) restart the units and check them

Flags (uninstall): removes units, files and what it recorded in <prefix>/state.json (ACLs, groups,
SELinux rules). Kept unless asked: data/ + backup/ (--purge-data), secrets/ (--purge-secrets: you type
"yes"; without a terminal --yes counts), the collector user (--purge, only if it created it).

Not yet available: sql, interactive questions (see docs/design.md, section 14).
`

// collectorSource: the collector of this release, downloaded once per command (plan + apply reuse it); the
// download directory is removed at the end.
func collectorSource() (*collector.Release, func()) {
	r := &collector.Release{Version: version.Version}
	dir, err := os.MkdirTemp("", "monitoring-collector-")
	if err != nil {
		return r, func() {}
	}
	r.Dir = dir
	return r, func() { os.RemoveAll(dir) }
}

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
	case "update":
		return update(args, stdout, stderr)
	case "install":
		return installCmd(args, stdout, stderr)
	case "uninstall":
		return uninstall(args, stdout, stderr)
	case "detect":
		return detectCmd(args, stdout, stderr)
	case "agent":
		return agentCmd(args, stdout, stderr)
	case "self-update":
		return selfUpdateCmd(args, stdout, stderr)
	case "generate":
		return generateCmd(args, stdout, stderr)
	case "sql":
		fmt.Fprintf(stderr, "monitoring-agent %s: not implemented yet (see docs/design.md, section 14)\n", cmd)
		return exitPlan
	default:
		fmt.Fprintf(stderr, "monitoring-agent: unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}
}

func planApply(apply bool, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("monitoring-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hostDir := fs.String("host-dir", "", "")
	answers := fs.String("answers", "", "")
	detectFile := fs.String("detect-json", "", "")
	siteDir := fs.String("site-dir", "", "")
	allowFile := fs.String("agent-allow", "", "")
	prefix := fs.String("prefix", "/opt/monitoring", "")
	user := fs.String("user", engine.DefaultUser, "")
	noFetch := fs.Bool("no-fetch", false, "")
	collectorFile := fs.String("collector-file", "", "")
	noSmoke := fs.Bool("no-smoke", false, "")
	noRollback := fs.Bool("no-rollback", false, "")
	start := fs.Bool("start", false, "")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *hostDir != "" && *answers != "" {
		fmt.Fprintln(stderr, "monitoring-agent: give --answers FILE or --host-dir DIR, not both")
		return exitUsage
	}
	if *start && !apply {
		fmt.Fprintln(stderr, "monitoring-agent: --start only works with apply")
		return exitUsage
	}
	var (
		d       engine.Desired
		secrets map[string]string
		p       ask.Prompter // set = interactive
		err     error
	)
	switch {
	case *hostDir != "":
		d, err = hostdir.Load(*hostDir)
	case *answers != "":
		var a generate.Answers
		if a, err = generate.LoadAnswers(*answers); err == nil {
			d, err = desiredFrom(stdout, a, *detectFile, *siteDir, inputs{prefix: *prefix, allow: allowFor(stdout, *allowFile, *prefix, a), keepCP: true})
		}
	default: // no answers file: ask on the terminal (previous answers are the defaults)
		tty, terr := openPrompter()
		if terr != nil {
			fmt.Fprintf(stderr, "monitoring-agent: %v (example: examples/app-host/answers.yaml)\n", terr)
			return exitUsage
		}
		defer tty.Close()
		p = tty
		d, secrets, err = interview(stdout, p, *prefix, *detectFile, *siteDir, inputs{prefix: *prefix, allow: *allowFile, keepCP: true})
	}
	if err != nil {
		fmt.Fprintf(stderr, "monitoring-agent: %v\n", err)
		return exitUsage
	}
	if apply {
		lk, err := lockInstall(*prefix)
		if err != nil {
			fmt.Fprintf(stderr, "monitoring-agent: %v\n", err)
			return exitUsage
		}
		defer lk.Release()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	src, cleanup := collectorSource()
	defer cleanup()
	opts := engine.Options{
		Prefix: *prefix, User: *user, Apply: apply, Start: *start, Fetch: !*noFetch, Smoke: !*noSmoke,
		Rollback: !*noRollback, SecretsInput: secrets, Collector: src, CollectorFile: *collectorFile,
		Out: stdout, Runner: sysexec.Runner{},
	}
	res, err := runEngine(ctx, opts, d)
	if err == nil && p != nil && !apply && res.Failures == 0 {
		// docs/design.md 6a: finish in one run, but only after a clean plan, the diff shown first
		yes, aerr := p.YesNo("\nApply now? (backup first, start, automatic rollback if it does not start)", true)
		if aerr == nil && yes {
			lk, lerr := lockInstall(*prefix)
			if lerr != nil {
				fmt.Fprintf(stderr, "monitoring-agent: %v\n", lerr)
				return exitUsage
			}
			defer lk.Release()
			opts.Apply, opts.Start, opts.Rollback = true, true, true
			opts.Smoke = false // the identical configuration passed the smoke run seconds ago
			res, err = runEngine(ctx, opts, d)
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "monitoring-agent: %v\n", err)
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

// update: the one-liner for a new release. Inputs come from the installation itself (<prefix>/answers.yaml,
// <prefix>/config/site.d/), so nothing has to be copied to the host. The host is scanned again (moved log
// files, new services). Plan first (validate + smoke run); apply + start + rollback only after a clean plan
// that changes something: an up-to-date host is not restarted (a restart resets the counters).
func update(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("monitoring-agent update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	planOnly := fs.Bool("plan", false, "")
	detectFile := fs.String("detect-json", "", "")
	prefix := fs.String("prefix", "/opt/monitoring", "")
	user := fs.String("user", engine.DefaultUser, "")
	noFetch := fs.Bool("no-fetch", false, "")
	collectorFile := fs.String("collector-file", "", "")
	noSmoke := fs.Bool("no-smoke", false, "")
	noRollback := fs.Bool("no-rollback", false, "")
	// v0.23.0: the new site.d to use instead of the installed one (root's overlay job stages it; not for people:
	// to change site.d by hand use plan / apply --site-dir)
	siteFrom := fs.String("site-dir", "", "")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "monitoring-agent update: unexpected argument %q (to change answers or site.d use plan / apply --answers)\n", fs.Arg(0))
		return exitUsage
	}
	saved := filepath.Join(*prefix, "answers.yaml")
	a, err := generate.LoadAnswers(saved)
	if os.IsNotExist(err) {
		fmt.Fprintf(stderr, "monitoring-agent update: %s is missing: install first (`monitoring-agent` asks, or `monitoring-agent apply --answers FILE --start`)\n", saved)
		return exitUsage
	}
	if err != nil {
		fmt.Fprintf(stderr, "monitoring-agent update: %v\n", err)
		return exitUsage
	}
	lk, err := lockInstall(*prefix)
	if err != nil {
		fmt.Fprintf(stderr, "monitoring-agent update: %v\n", err)
		return exitUsage
	}
	defer lk.Release()
	siteDir := filepath.Join(*prefix, "config", "site.d")
	if *siteFrom != "" {
		siteDir = *siteFrom
		fmt.Fprintf(stdout, "update: answers from %s, site overlay from %s (the new set)\n", saved, siteDir)
	} else {
		fmt.Fprintf(stdout, "update: answers from %s, site overlay from %s (kept as installed)\n", saved, siteDir)
	}
	in := inputs{prefix: *prefix}
	if t := filepath.Join(*prefix, filepath.FromSlash(generate.AllowFile)); fileExists(t) {
		in.allow = t // the installed agent allowlist template stays
	}
	d, err := desiredFrom(stdout, a, *detectFile, siteDir, in)
	if err != nil {
		fmt.Fprintf(stderr, "monitoring-agent update: %v\n", err)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	src, cleanup := collectorSource()
	defer cleanup()
	opts := engine.Options{
		Prefix: *prefix, User: *user, Fetch: !*noFetch, Smoke: !*noSmoke, Rollback: !*noRollback,
		Collector: src, CollectorFile: *collectorFile,
		Out: stdout, Runner: sysexec.Runner{}, CheckHint: "-",
	}
	res, err := runEngine(ctx, opts, d)
	switch {
	case err != nil:
		fmt.Fprintf(stderr, "monitoring-agent update: %v\n", err)
		if errors.Is(err, context.Canceled) {
			return exitPlan
		}
		return exitUsage
	case res.Failures > 0:
		fmt.Fprintln(stdout, "\nupdate: the plan has failures: nothing was changed.")
		return exitPlan
	case res.Changes == 0:
		fmt.Fprintln(stdout, "\nupdate: up to date: nothing to change, nothing restarted.")
		return exitOK
	case *planOnly && res.NoRestart:
		fmt.Fprintln(stdout, "\nupdate: only the installer version / the service inventory changed (configuration identical): the update writes them, no restart.")
		return exitOK
	case *planOnly:
		fmt.Fprintf(stdout, "\nupdate: %d change(s) planned. Apply: run the same command without --plan.\n", res.Changes)
		return exitOK
	}
	// only VERSION / inventory.json differ: the running collector already has this configuration -> write them, do
	// not restart (a restart resets cumulative counters for nothing)
	opts.Apply, opts.Start = true, !res.NoRestart
	opts.Smoke = false // the identical configuration passed the smoke run seconds ago
	noRestart := res.NoRestart
	if res, err = runEngine(ctx, opts, d); err != nil {
		fmt.Fprintf(stderr, "monitoring-agent update: %v\n", err)
		return exitUsage
	}
	if res.Failures > 0 || res.RolledBack {
		return exitPlan
	}
	if noRestart {
		fmt.Fprintln(stdout, "\nupdate: only the installer version / the service inventory changed: written, collector NOT restarted.")
	}
	return exitOK
}

// promptCloser is a Prompter on a terminal.
type promptCloser interface {
	ask.Prompter
	Close() error
}

// openPrompter is replaced in tests.
var openPrompter = func() (promptCloser, error) { return ask.OpenTTY() }

// scan detects live, or reads a saved "monitoring-agent detect --json".
func scan(detectPath string) (generate.Host, error) {
	if detectPath == "" {
		snap := detect.Collect(detectSource)
		return generate.Host{Findings: detect.Detect(snap, detectSource), TimeZone: snap.TimeZone, OS: snap.OS,
			Listen: snap.Listens}, nil
	}
	b, err := os.ReadFile(detectPath)
	if err != nil {
		return generate.Host{}, err
	}
	var dj detectJSON
	if err := json.Unmarshal(b, &dj); err != nil {
		return generate.Host{}, fmt.Errorf("%s: %w", detectPath, err)
	}
	return generate.Host{Findings: dj.Findings, TimeZone: dj.TimeZone, OS: dj.OS, Listen: dj.Listen}, nil
}

// inputs besides the answers: install prefix (agent state) and the agent allowlist template file.
type inputs struct {
	prefix string
	allow  string // --agent-allow FILE ("" = none)
	// keepCP (v0.23.0, plan / apply): the installed control-plane overlays (config/site.d/cp-*) stay; the host
	// owner's --site-dir may not contain cp-* files. `update` (and root's overlay job) uses the given set as is.
	keepCP bool
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// allowFor (v0.22.5): the allowlist template of a plan / apply. Without --agent-allow the INSTALLED template stays (an
// apply that forgot the flag removed it and the agent dropped every probe outside the host extras); "none" removes it.
func allowFor(w io.Writer, flag, prefix string, a generate.Answers) string {
	switch {
	case flag == "none":
		return ""
	case flag != "":
		return flag
	case a.Agent == nil:
		return ""
	}
	if t := filepath.Join(prefix, filepath.FromSlash(generate.AllowFile)); fileExists(t) {
		fmt.Fprintf(w, "  ok    agent allowlist template: the installed %s is kept (--agent-allow FILE changes it, --agent-allow none removes it)\n", generate.AllowFile)
		return t
	}
	return ""
}

// desiredFrom generates the host part from answers and builds what the engine installs, incl. answers.yaml.
func desiredFrom(w io.Writer, a generate.Answers, detectPath, siteDir string, in inputs) (engine.Desired, error) {
	h, err := scan(detectPath)
	if err != nil {
		return engine.Desired{}, err
	}
	return build(w, h, a, siteDir, in)
}

// agentInputs (v0.13.0): with an agent section, the effective allowlist (template + host extras, printed) and the
// probe list the agent applied last, so the generated Cloudprober files are the agent's.
func agentInputs(w io.Writer, h *generate.Host, a generate.Answers, in inputs) (*engine.Agent, error) {
	if a.Agent == nil {
		if in.allow != "" {
			return nil, fmt.Errorf("--agent-allow without an agent section in the answers")
		}
		return nil, nil
	}
	var tmpl generate.Allow
	var raw []byte
	if in.allow != "" {
		var err error
		if tmpl, err = generate.LoadAllow(in.allow); err != nil {
			return nil, err
		}
		if raw, err = os.ReadFile(in.allow); err != nil {
			return nil, err
		}
	}
	h.AgentAllow = tmpl.Merge(a.Agent.Allow)
	fmt.Fprintf(w, "  ok    agent allowlist: %s\n", h.AgentAllow)
	if in.prefix != "" {
		st, err := agent.LoadState(in.prefix)
		if err != nil {
			return nil, fmt.Errorf("%s/%s: %w", in.prefix, agent.StateFile, err)
		}
		h.AgentProbes = st.Probes
		if st.Revision > 0 {
			fmt.Fprintf(w, "  ok    agent: applied revision %d kept in the Cloudprober files\n", st.Revision)
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return &engine.Agent{AllowTemplate: raw, Binary: exe}, nil
}

func build(w io.Writer, h generate.Host, a generate.Answers, siteDir string, in inputs) (engine.Desired, error) {
	ag, err := agentInputs(w, &h, a, in)
	if err != nil {
		return engine.Desired{}, err
	}
	g, err := generate.Generate(h, a)
	if err != nil {
		return engine.Desired{}, err
	}
	printGenerated(w, g)
	site, err := hostdir.LoadSite(siteDir)
	if err != nil {
		return engine.Desired{}, err
	}
	if in.keepCP {
		if site, err = keepControlPlaneSite(w, site, in.prefix); err != nil {
			return engine.Desired{}, err
		}
	}
	d, err := hostdir.Build(g.HostYAML, g.HostEnv, site, "generated")
	if err != nil {
		return d, err
	}
	if p := g.Probes; p != nil {
		d.Probes = &engine.Probes{Config: p.Config, Targets: p.Targets, Ping: p.Ping}
	}
	d.Agent = ag
	d.Inventory = g.Inventory
	d.Answers, err = a.Marshal()
	return d, err
}

// interview: scan, ask (saved answers = defaults), generate; ask for secrets when the secrets file is missing.
func interview(w io.Writer, p ask.Prompter, prefix, detectPath, siteDir string, in inputs) (engine.Desired, map[string]string, error) {
	h, err := scan(detectPath)
	if err != nil {
		return engine.Desired{}, nil, err
	}
	var prev generate.Answers
	saved := filepath.Join(prefix, "answers.yaml")
	if _, err := os.Stat(saved); err == nil {
		if prev, err = generate.LoadAnswers(saved); err != nil {
			return engine.Desired{}, nil, err
		}
		p.Say("defaults from %s\n", saved)
	}
	a, err := ask.Interview(h.Findings, prev, p)
	if err != nil {
		return engine.Desired{}, nil, err
	}
	d, err := build(w, h, a, siteDir, in)
	if err != nil {
		return d, nil, err
	}
	var secrets map[string]string
	if fi, err := os.Stat(filepath.Join(prefix, "secrets", "collector.env")); err != nil || fi.Size() == 0 {
		if secrets, err = ask.Secrets(p, d.SecretKeys, ""); err != nil {
			return d, nil, err
		}
	}
	return d, secrets, nil
}

// detectSource is replaced in tests.
var detectSource detect.Source = detect.OS{}

// detectJSON is the `monitoring-agent detect --json` format; `--detect-json FILE` reads it back (offline generation).
type detectJSON struct {
	OS       string           `json:"os"`
	TimeZone string           `json:"time_zone"`
	Ports    []int            `json:"listening_ports"`
	Listen   []detect.Listen  `json:"listen,omitempty"` // v0.15.0: with the bind address (inventory)
	Notes    []string         `json:"notes,omitempty"`
	Findings []detect.Finding `json:"findings"`
}

// hostPart detects (live, or from a saved "monitoring-agent detect --json") and generates host.yaml + host.env.
func hostPart(answersPath, detectPath string) (generate.Output, error) {
	a, err := generate.LoadAnswers(answersPath)
	if err != nil {
		return generate.Output{}, err
	}
	h, err := scan(detectPath)
	if err != nil {
		return generate.Output{}, err
	}
	return generate.Generate(h, a)
}

func printGenerated(w io.Writer, g generate.Output) {
	fmt.Fprintf(w, "== 0. detect + generate\n  ok    monitoring: %s\n", orNone(g.Enabled))
	for _, d := range g.Defaults {
		fmt.Fprintf(w, "  DEFAULT %s  (set it in the answers file to silence this)\n", d)
	}
}

func orNone(xs []string) string {
	if len(xs) == 0 {
		return "host metrics only (no known service found)"
	}
	return strings.Join(xs, ", ")
}

func generateCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("monitoring-agent generate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	answers := fs.String("answers", "", "")
	detectFile := fs.String("detect-json", "", "")
	out := fs.String("out", "", "")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *answers == "" {
		fmt.Fprintln(stderr, "monitoring-agent generate: --answers FILE is required")
		return exitUsage
	}
	g, err := hostPart(*answers, *detectFile)
	if err != nil {
		fmt.Fprintf(stderr, "monitoring-agent: %v\n", err)
		return exitUsage
	}
	if *out == "" {
		fmt.Fprintf(stdout, "# ---- host.yaml\n%s\n# ---- host.env\n%s", g.HostYAML, g.HostEnv)
		printGenerated(stderr, g)
		return exitOK
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintf(stderr, "monitoring-agent: %v\n", err)
		return exitUsage
	}
	for name, b := range map[string][]byte{"host.yaml": g.HostYAML, "host.env": g.HostEnv} {
		if err := os.WriteFile(filepath.Join(*out, name), b, 0o644); err != nil {
			fmt.Fprintf(stderr, "monitoring-agent: %v\n", err)
			return exitUsage
		}
	}
	printGenerated(stdout, g)
	fmt.Fprintf(stdout, "  ok    written to %s (host.yaml, host.env). Nothing installed.\n", *out)
	return exitOK
}

func detectCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("monitoring-agent detect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	snap := detect.Collect(detectSource)
	found := detect.Detect(snap, detectSource)
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(detectJSON{snap.OS, snap.TimeZone, snap.PortsListening(), snap.Listens, snap.Notes, found}); err != nil {
			fmt.Fprintf(stderr, "monitoring-agent: %v\n", err)
			return exitUsage
		}
		return exitOK
	}
	detect.Print(stdout, snap, found)
	fmt.Fprintln(stdout, "\nRead-only: nothing was changed. Next: `sudo monitoring-agent` (asks, then plans) or `sudo monitoring-agent plan --answers FILE`.")
	return exitOK
}

func uninstall(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("monitoring-agent uninstall", flag.ContinueOnError)
	fs.SetOutput(stderr)
	prefix := fs.String("prefix", "/opt/monitoring", "")
	user := fs.String("user", engine.DefaultUser, "")
	yes := fs.Bool("yes", false, "")
	purgeData := fs.Bool("purge-data", false, "")
	purgeSecrets := fs.Bool("purge-secrets", false, "")
	purgeUser := fs.Bool("purge", false, "")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	// Secrets cannot be recreated by monitoring-agent: a typed "yes" on the terminal; in automation (no terminal) the
	// two explicit flags --purge-secrets --yes are the confirmation.
	if *purgeSecrets && *yes {
		if answer, isTTY := confirm("Delete " + *prefix + "/secrets (backend + database credentials)? Type yes: "); isTTY && answer != "yes" {
			fmt.Fprintln(stderr, "monitoring-agent: secrets kept (answer was not yes); nothing removed")
			return exitPlan
		}
	}
	res, err := runUninstall(engine.Options{
		Prefix: *prefix, User: *user, Apply: *yes, Out: stdout, Runner: sysexec.Runner{},
	}, engine.UninstallOptions{PurgeData: *purgeData, PurgeSecrets: *purgeSecrets, PurgeUser: *purgeUser})
	if err != nil {
		fmt.Fprintf(stderr, "monitoring-agent: %v\n", err)
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

// keepControlPlaneSite (v0.23.0): the overlays the control plane installed (config/site.d/<generate.SitePrefix>*)
// belong to it: a plan / apply with the host owner's --site-dir keeps them (it does not own them); the host owner's
// directory may not bring files with that prefix.
func keepControlPlaneSite(w io.Writer, site map[string][]byte, prefix string) (map[string][]byte, error) {
	for n := range site {
		if strings.HasPrefix(n, generate.SitePrefix) {
			return nil, fmt.Errorf("--site-dir: %s: names starting with %q belong to the control plane's overlays", n, generate.SitePrefix)
		}
	}
	installed, err := hostdir.LoadSite(filepath.Join(prefix, "config", "site.d"))
	if err != nil {
		return nil, err
	}
	var kept []string
	for n, b := range installed {
		if !strings.HasPrefix(n, generate.SitePrefix) {
			continue
		}
		if site == nil {
			site = map[string][]byte{}
		}
		site[n] = b
		kept = append(kept, n)
	}
	if len(kept) > 0 {
		sort.Strings(kept)
		fmt.Fprintf(w, "site.d: the control plane's overlays are kept: %s\n", strings.Join(kept, ", "))
	}
	return site, nil
}
