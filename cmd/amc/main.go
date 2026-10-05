// Command amc (auto-mon-collector) scans a Linux host, proposes what to monitor, generates the configuration
// for the official OpenTelemetry Collector (otelcol-contrib) and installs it on request. See docs/design.md.
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
	"strings"
	"syscall"

	"github.com/NABIXcorp/auto-mon-collector/internal/ask"
	"github.com/NABIXcorp/auto-mon-collector/internal/detect"
	"github.com/NABIXcorp/auto-mon-collector/internal/engine"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
	"github.com/NABIXcorp/auto-mon-collector/internal/hostdir"
	"github.com/NABIXcorp/auto-mon-collector/internal/sysexec"
	"github.com/NABIXcorp/auto-mon-collector/internal/version"
)

const usage = `auto-mon-collector (amc): host discovery installer for otelcol-contrib

Usage:
  amc plan  --answers FILE [flags]           detect + generate + diff + validate + smoke run; changes nothing
  amc apply --answers FILE [--start] [flags] the same, then install (backup first), optionally (re)start
  amc generate --answers FILE [--out DIR]    only write host.yaml + host.env (nothing installed)
  amc detect [--json]                        read-only: which services this host runs (needs root)
  amc uninstall [--yes] [--purge-data] [--purge-secrets] [--purge]   check mode unless --yes
  amc version

Flags (plan / apply / generate):
  --answers FILE      what a scan cannot know: Oracle service name + user, HTTP checks, services on/off
  --detect-json FILE  use a saved "amc detect --json" instead of scanning (offline / review)
  --site-dir DIR      operator overlay *.yaml, installed as config/site.d/ (plan / apply)
  --host-dir DIR      instead of --answers: a prepared host part (host.yaml, host.env, site.d/)
  --prefix DIR        install root (default /opt/monitoring)
  --user NAME         collector user (default otelcol-contrib)
  --no-fetch          do not download the pinned collector when it is missing or another version
  --no-smoke          skip the 25 s test run of the new config (local sink, nothing sent to the backend)
  --no-rollback       (apply --start) keep the new state even when a unit does not start
  --start             (apply) restart the units and check them

Flags (uninstall): removes units, files and what amc recorded in <prefix>/amc-state.json (ACLs, groups,
SELinux rules). Kept unless asked: data/ + backup/ (--purge-data), secrets/ (--purge-secrets: you type
"yes"; without a terminal --yes counts), the collector user (--purge, only if amc created it).

Not yet available: sql, interactive questions (see docs/design.md, section 14).
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
	case "detect":
		return detectCmd(args, stdout, stderr)
	case "generate":
		return generateCmd(args, stdout, stderr)
	case "sql":
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
	answers := fs.String("answers", "", "")
	detectFile := fs.String("detect-json", "", "")
	siteDir := fs.String("site-dir", "", "")
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
	if *hostDir != "" && *answers != "" {
		fmt.Fprintln(stderr, "amc: give --answers FILE or --host-dir DIR, not both")
		return exitUsage
	}
	if *start && !apply {
		fmt.Fprintln(stderr, "amc: --start only works with apply")
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
			d, err = desiredFrom(stdout, a, *detectFile, *siteDir)
		}
	default: // no answers file: ask on the terminal (previous answers are the defaults)
		tty, terr := openPrompter()
		if terr != nil {
			fmt.Fprintf(stderr, "amc: %v (example: examples/app-host/answers.yaml)\n", terr)
			return exitUsage
		}
		defer tty.Close()
		p = tty
		d, secrets, err = interview(stdout, p, *prefix, *detectFile, *siteDir)
	}
	if err != nil {
		fmt.Fprintf(stderr, "amc: %v\n", err)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	opts := engine.Options{
		Prefix: *prefix, User: *user, Apply: apply, Start: *start, Fetch: !*noFetch, Smoke: !*noSmoke,
		Rollback: !*noRollback, SecretsInput: secrets,
		Out: stdout, Runner: sysexec.Runner{},
	}
	res, err := runEngine(ctx, opts, d)
	if err == nil && p != nil && !apply && res.Failures == 0 {
		// docs/design.md 6a: finish in one run, but only after a clean plan, the diff shown first
		yes, aerr := p.YesNo("\nApply now? (backup first, start, automatic rollback if it does not start)", true)
		if aerr == nil && yes {
			opts.Apply, opts.Start, opts.Rollback = true, true, true
			opts.Smoke = false // the identical configuration passed the smoke run seconds ago
			res, err = runEngine(ctx, opts, d)
		}
	}
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

// promptCloser is a Prompter on a terminal.
type promptCloser interface {
	ask.Prompter
	Close() error
}

// openPrompter is replaced in tests.
var openPrompter = func() (promptCloser, error) { return ask.OpenTTY() }

// scan detects live, or reads a saved "amc detect --json".
func scan(detectPath string) (generate.Host, error) {
	if detectPath == "" {
		snap := detect.Collect(detectSource)
		return generate.Host{Findings: detect.Detect(snap, detectSource), TimeZone: snap.TimeZone}, nil
	}
	b, err := os.ReadFile(detectPath)
	if err != nil {
		return generate.Host{}, err
	}
	var dj detectJSON
	if err := json.Unmarshal(b, &dj); err != nil {
		return generate.Host{}, fmt.Errorf("%s: %w", detectPath, err)
	}
	return generate.Host{Findings: dj.Findings, TimeZone: dj.TimeZone}, nil
}

// desiredFrom generates the host part from answers and builds what the engine installs, incl. answers.yaml.
func desiredFrom(w io.Writer, a generate.Answers, detectPath, siteDir string) (engine.Desired, error) {
	h, err := scan(detectPath)
	if err != nil {
		return engine.Desired{}, err
	}
	return build(w, h, a, siteDir)
}

func build(w io.Writer, h generate.Host, a generate.Answers, siteDir string) (engine.Desired, error) {
	g, err := generate.Generate(h, a)
	if err != nil {
		return engine.Desired{}, err
	}
	printGenerated(w, g)
	site, err := hostdir.LoadSite(siteDir)
	if err != nil {
		return engine.Desired{}, err
	}
	d, err := hostdir.Build(g.HostYAML, g.HostEnv, site, "generated")
	if err != nil {
		return d, err
	}
	d.Answers, err = a.Marshal()
	return d, err
}

// interview: scan, ask (saved answers = defaults), generate; ask for secrets when the secrets file is missing.
func interview(w io.Writer, p ask.Prompter, prefix, detectPath, siteDir string) (engine.Desired, map[string]string, error) {
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
	d, err := build(w, h, a, siteDir)
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

// detectJSON is the `amc detect --json` format; `--detect-json FILE` reads it back (offline generation).
type detectJSON struct {
	OS       string           `json:"os"`
	TimeZone string           `json:"time_zone"`
	Ports    []int            `json:"listening_ports"`
	Notes    []string         `json:"notes,omitempty"`
	Findings []detect.Finding `json:"findings"`
}

// hostPart detects (live, or from a saved "amc detect --json") and generates host.yaml + host.env.
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
	fs := flag.NewFlagSet("amc generate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	answers := fs.String("answers", "", "")
	detectFile := fs.String("detect-json", "", "")
	out := fs.String("out", "", "")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *answers == "" {
		fmt.Fprintln(stderr, "amc generate: --answers FILE is required")
		return exitUsage
	}
	g, err := hostPart(*answers, *detectFile)
	if err != nil {
		fmt.Fprintf(stderr, "amc: %v\n", err)
		return exitUsage
	}
	if *out == "" {
		fmt.Fprintf(stdout, "# ---- host.yaml\n%s\n# ---- host.env\n%s", g.HostYAML, g.HostEnv)
		printGenerated(stderr, g)
		return exitOK
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintf(stderr, "amc: %v\n", err)
		return exitUsage
	}
	for name, b := range map[string][]byte{"host.yaml": g.HostYAML, "host.env": g.HostEnv} {
		if err := os.WriteFile(filepath.Join(*out, name), b, 0o644); err != nil {
			fmt.Fprintf(stderr, "amc: %v\n", err)
			return exitUsage
		}
	}
	printGenerated(stdout, g)
	fmt.Fprintf(stdout, "  ok    written to %s (host.yaml, host.env). Nothing installed.\n", *out)
	return exitOK
}

func detectCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("amc detect", flag.ContinueOnError)
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
		if err := enc.Encode(detectJSON{snap.OS, snap.TimeZone, snap.PortsListening(), snap.Notes, found}); err != nil {
			fmt.Fprintf(stderr, "amc: %v\n", err)
			return exitUsage
		}
		return exitOK
	}
	detect.Print(stdout, snap, found)
	fmt.Fprintln(stdout, "\nRead-only: nothing was changed. (Generating the host config from this comes next.)")
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
