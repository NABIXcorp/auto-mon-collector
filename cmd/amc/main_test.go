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

func TestRun(t *testing.T) {
	cases := []struct {
		args     []string
		code     int
		inStdout string
		inStderr string
	}{
		{[]string{"version"}, exitOK, "auto-mon-collector", ""},
		{[]string{"help"}, exitOK, "Usage:", ""},
		{nil, exitUsage, "", "--host-dir is required"}, // default command = plan
		{[]string{"plan", "--start", "--host-dir", "x"}, exitUsage, "", "only works with apply"},
		{[]string{"detect"}, exitPlan, "", "not implemented"},
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
