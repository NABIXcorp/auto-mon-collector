package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/internal/engine"
)

// installedPrefix: what an earlier apply left behind (answers.yaml + one site overlay).
func installedPrefix(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	a, err := os.ReadFile("../../examples/app-host/answers.yaml")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "answers.yaml"), a, 0o644)
	os.MkdirAll(filepath.Join(dir, "config", "site.d"), 0o755)
	os.WriteFile(filepath.Join(dir, "config", "site.d", "10-site.yaml"), []byte("processors: {}\n"), 0o644)
	return dir
}

func TestUpdate(t *testing.T) {
	defer func() { runEngine = engine.Run }()
	cases := []struct {
		name    string
		extra   []string
		plan    engine.Result // result of the first (check) run
		code    int
		runs    int
		inOut   string
		missing bool // no answers.yaml in the prefix
	}{
		{name: "changes: plan, then apply + start", plan: engine.Result{Changes: 3}, code: exitOK, runs: 2},
		{name: "up to date: no restart", plan: engine.Result{}, code: exitOK, runs: 1, inOut: "up to date"},
		{name: "--plan stops after the plan", extra: []string{"--plan"}, plan: engine.Result{Changes: 2}, code: exitOK, runs: 1, inOut: "2 change(s) planned"},
		{name: "failures: nothing applied", plan: engine.Result{Failures: 1, Changes: 2}, code: exitPlan, runs: 1, inOut: "nothing was changed"},
		{name: "not installed", missing: true, code: exitUsage, runs: 0},
		{name: "only VERSION: apply without restart", plan: engine.Result{Changes: 1, VersionOnly: true}, code: exitOK, runs: 2, inOut: "NOT restarted"},
		{name: "--plan, only VERSION", extra: []string{"--plan"}, plan: engine.Result{Changes: 1, VersionOnly: true}, code: exitOK, runs: 1, inOut: "no restart"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prefix := installedPrefix(t)
			if c.missing {
				os.Remove(filepath.Join(prefix, "answers.yaml"))
			}
			var calls []engine.Options
			var got engine.Desired
			runEngine = func(_ context.Context, o engine.Options, d engine.Desired) (engine.Result, error) {
				calls, got = append(calls, o), d
				if len(calls) == 1 {
					return c.plan, nil
				}
				return engine.Result{Applied: true}, nil
			}
			var out, errb bytes.Buffer
			args := append([]string{"update", "--detect-json", "../../examples/app-host/detect.json", "--prefix", prefix}, c.extra...)
			if code := run(args, &out, &errb); code != c.code || len(calls) != c.runs {
				t.Fatalf("code %d (want %d), %d engine runs (want %d)\nstdout %s\nstderr %s", code, c.code, len(calls), c.runs, out.String(), errb.String())
			}
			if !strings.Contains(out.String(), c.inOut) {
				t.Errorf("stdout lacks %q:\n%s", c.inOut, out.String())
			}
			if c.runs == 0 {
				return
			}
			if calls[0].Apply || !calls[0].Smoke || calls[0].Prefix != prefix {
				t.Errorf("first run must be a check with smoke run: %+v", calls[0])
			}
			if calls[0].CheckHint != "-" {
				t.Errorf("update prints its own hint, not the engine's `amc apply`: %q", calls[0].CheckHint)
			}
			if c.runs == 2 && (!calls[1].Apply || calls[1].Start == c.plan.VersionOnly || !calls[1].Rollback || calls[1].Smoke) {
				t.Errorf("second run = apply + rollback, start unless only VERSION changed, no second smoke run: %+v", calls[1])
			}
			if string(got.Site["10-site.yaml"]) != "processors: {}\n" || len(got.Site) != 1 {
				t.Errorf("the installed site.d must be kept: %v", got.Site)
			}
			if !strings.Contains(string(got.HostEnv), "ORACLE_SERVICE=") || got.Answers == nil {
				t.Errorf("host part must come from the saved answers: %s", got.HostEnv)
			}
		})
	}
}

func TestUpdateRejectsArguments(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"update", "--prefix", t.TempDir(), "answers.yaml"}, &out, &errb); code != exitUsage ||
		!strings.Contains(errb.String(), "unexpected argument") {
		t.Errorf("code %d stderr %s", code, errb.String())
	}
}
