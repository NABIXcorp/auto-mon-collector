package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/internal/ask"
	"github.com/NABIXcorp/auto-mon-collector/internal/engine"
)

func TestRun(t *testing.T) {
	cases := []struct {
		args     []string
		code     int
		inStdout string
		inStderr string
	}{
		{[]string{"version"}, exitOK, "auto-mon-collector", ""},
		{[]string{"help"}, exitOK, "Usage:", ""},
		{nil, exitUsage, "", "give --answers FILE"}, // default command = plan
		{[]string{"plan", "--start", "--host-dir", "x"}, exitUsage, "", "only works with apply"},
		{[]string{"sql"}, exitPlan, "", "not implemented"},
		{[]string{"nope"}, exitUsage, "", "unknown command"},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		if got := run(c.args, &out, &errb); got != c.code {
			t.Errorf("run(%v) = %d, want %d (stderr %q)", c.args, got, c.code, errb.String())
		}
		if !strings.Contains(out.String(), c.inStdout) || !strings.Contains(errb.String(), c.inStderr) {
			t.Errorf("run(%v): stdout %q stderr %q", c.args, out.String(), errb.String())
		}
	}
}

func TestPlanApplyPassesOptions(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "host.yaml"), []byte("receivers: {}\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "host.env"), []byte("ORACLE_MON=off\n"), 0o644)
	var got engine.Options
	runEngine = func(_ context.Context, o engine.Options, _ engine.Desired) (engine.Result, error) {
		got = o
		return engine.Result{Failures: 1}, nil
	}
	defer func() { runEngine = engine.Run }()
	var out, errb bytes.Buffer
	code := run([]string{"apply", "--host-dir", dir, "--start", "--no-fetch", "--prefix", "/srv/mon"}, &out, &errb)
	if code != exitPlan {
		t.Errorf("failures must give exit %d, got %d", exitPlan, code)
	}
	if !got.Apply || !got.Start || got.Fetch || got.Prefix != "/srv/mon" || got.User != "otelcol-contrib" {
		t.Errorf("options = %+v", got)
	}
}

func TestUninstallPurgeSecretsNeedsATypedYes(t *testing.T) {
	called := false
	runUninstall = func(engine.Options, engine.UninstallOptions) (engine.Result, error) {
		called = true
		return engine.Result{}, nil
	}
	defer func() { runUninstall, confirm = engine.Uninstall, confirmTTY }()

	confirm = func(string) (string, bool) { return "no", true } // a terminal, answer is not "yes"
	var out, errb bytes.Buffer
	if code := run([]string{"uninstall", "--yes", "--purge-secrets"}, &out, &errb); code != exitPlan || called {
		t.Errorf("must stop without a typed yes: code %d called %v", code, called)
	}
	confirm = func(string) (string, bool) { return "", false } // no terminal: the two flags are the confirmation
	if code := run([]string{"uninstall", "--yes", "--purge-secrets"}, &out, &errb); code != exitOK || !called {
		t.Errorf("automation path: code %d called %v", code, called)
	}
}

func TestUninstallDefaultIsCheckMode(t *testing.T) {
	var got engine.Options
	var gotU engine.UninstallOptions
	runUninstall = func(o engine.Options, u engine.UninstallOptions) (engine.Result, error) {
		got, gotU = o, u
		return engine.Result{}, nil
	}
	defer func() { runUninstall = engine.Uninstall }()
	var out, errb bytes.Buffer
	run([]string{"uninstall", "--purge-data"}, &out, &errb)
	if got.Apply || !gotU.PurgeData || gotU.PurgeSecrets || gotU.PurgeUser {
		t.Errorf("options %+v %+v", got, gotU)
	}
}

type scriptTTY struct{ *ask.Script }

func (scriptTTY) Close() error { return nil }

func TestInteractivePlanThenApplyNow(t *testing.T) {
	s := &ask.Script{Answers: []string{
		"Shop prod",  // project
		"",           // monitor [oracle, redis, tomcat]? (all detected: keep)
		"apppdb", "", // oracle service, user (default otel_mon)
		"",     // non-CDB database? (default no)
		"",     // HTTP checks: default http://127.0.0.1:8080/
		"", "", // Tomcat logs: what the scan found
		"https://backend.example.com/api/x", "Basic dGVzdA==", "pw123456", // secrets file missing
		"y", // Apply now?
	}}
	openPrompter = func() (promptCloser, error) { return scriptTTY{s}, nil }
	var calls []engine.Options
	var got engine.Desired
	runEngine = func(_ context.Context, o engine.Options, d engine.Desired) (engine.Result, error) {
		calls, got = append(calls, o), d
		return engine.Result{}, nil
	}
	defer func() { runEngine, openPrompter = engine.Run, func() (promptCloser, error) { return ask.OpenTTY() } }()

	var out, errb bytes.Buffer
	code := run([]string{"plan", "--detect-json", "../../examples/app-host/detect.json", "--prefix", t.TempDir()}, &out, &errb)
	if code != exitOK || len(calls) != 2 {
		t.Fatalf("code %d, %d engine runs\nstderr %s\ntranscript %s", code, len(calls), errb.String(), s.Out.String())
	}
	if calls[0].Apply || !calls[0].Smoke || calls[0].SecretsInput["ORACLE_MON_PASSWORD"] != "pw123456" {
		t.Errorf("first run must be a plan with smoke run and the typed secrets: %+v", calls[0])
	}
	if !calls[1].Apply || !calls[1].Start || !calls[1].Rollback || calls[1].Smoke {
		t.Errorf("Apply now = apply + start + rollback, no second smoke run: %+v", calls[1])
	}
	if !strings.Contains(string(got.Answers), "service: apppdb") || strings.Contains(string(got.Answers), "pw123456") {
		t.Errorf("answers.yaml: %s", got.Answers)
	}
	if !strings.Contains(string(got.Answers), "project: Shop prod") || strings.Contains(string(got.Answers), "access_log") {
		t.Errorf("answers.yaml: project asked, scanned logs not repeated: %s", got.Answers)
	}
	if !strings.Contains(string(got.HostEnv), "ORACLE_SERVICE=apppdb") || !strings.Contains(string(got.HostEnv), "REDIS_PORT=6380") {
		t.Errorf("host.env: %s", got.HostEnv)
	}
	if strings.Contains(out.String()+s.Out.String(), "dGVzdA==") || strings.Contains(out.String()+s.Out.String(), "pw123456") {
		t.Error("a typed secret reached the output")
	}
}

func TestInteractiveApplyNowNo(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "secrets"), 0o700)
	os.WriteFile(filepath.Join(dir, "secrets", "collector.env"), []byte("OO_ENDPOINT=x\n"), 0o600) // exists: no secret questions
	s := &ask.Script{Answers: []string{"", "", "apppdb", "", "", "", "", "", "n"}}                 // project .. logs, Apply now? n
	openPrompter = func() (promptCloser, error) { return scriptTTY{s}, nil }
	n := 0
	runEngine = func(context.Context, engine.Options, engine.Desired) (engine.Result, error) {
		n++
		return engine.Result{}, nil
	}
	defer func() { runEngine, openPrompter = engine.Run, func() (promptCloser, error) { return ask.OpenTTY() } }()
	var out, errb bytes.Buffer
	if code := run([]string{"--detect-json", "../../examples/app-host/detect.json", "--prefix", dir}, &out, &errb); code != exitOK || n != 1 {
		t.Errorf("answer n: plan only (code %d, %d runs) %s", code, n, errb.String())
	}
}
