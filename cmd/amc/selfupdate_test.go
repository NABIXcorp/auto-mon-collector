package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/selfupdate"
)

func TestSelfUpdateCommand(t *testing.T) {
	var got *selfupdate.Options
	result := "ok"
	oldRun, oldUID := runSelfUpdate, geteuid
	runSelfUpdate = func(_ context.Context, o selfupdate.Options) agent.UpdateResult {
		got = &o
		return agent.UpdateResult{Result: result}
	}
	defer func() { runSelfUpdate, geteuid = oldRun, oldUID }()
	run1 := func(args ...string) (int, string) {
		var out, errb bytes.Buffer
		code := run(append([]string{"self-update"}, args...), &out, &errb)
		return code, errb.String()
	}

	geteuid = func() int { return 1000 }
	if code, e := run1("--request", "/opt/monitoring/agent/update-request.json"); code != exitUsage || !strings.Contains(e, "root") || got != nil {
		t.Errorf("not root: %d %s", code, e)
	}
	geteuid = func() int { return 0 }
	if code, e := run1(); code != exitUsage || !strings.Contains(e, "--request") {
		t.Errorf("no request: %d %s", code, e)
	}
	// no URL, key or version from the command line: only the request file and the prefix
	for _, bad := range [][]string{{"--request", "r.json", "--url", "https://example.com/"}, {"--request", "r.json", "v0.16.1"}} {
		if code, _ := run1(bad...); code != exitUsage || got != nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if code, _ := run1("--request", "/tmp/r.json", "--prefix", "/srv/mon"); code != exitOK || got == nil ||
		got.Request != "/tmp/r.json" || got.Prefix != "/srv/mon" || got.Running == "" {
		t.Errorf("ok: %d %+v", code, got)
	}
	result = "rolled_back"
	if code, _ := run1("--request", "/tmp/r.json"); code != exitPlan {
		t.Errorf("rolled back: exit %d", code)
	}
}
