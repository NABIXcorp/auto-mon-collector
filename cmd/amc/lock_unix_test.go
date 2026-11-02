//go:build unix

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/internal/engine"
	"github.com/NABIXcorp/auto-mon-collector/internal/lockfile"
)

// v0.16.0: apply and update refuse to run while another amc (e.g. a self-update) holds <prefix>/.amc.lock.
func TestApplyAndUpdateWaitForTheLock(t *testing.T) {
	pre := t.TempDir()
	if err := os.WriteFile(filepath.Join(pre, "answers.yaml"), []byte("project: demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	host := t.TempDir()
	os.WriteFile(filepath.Join(host, "host.yaml"), []byte("receivers: {}\n"), 0o644)
	os.WriteFile(filepath.Join(host, "host.env"), []byte("ORACLE_MON=off\n"), 0o644)
	ran := 0
	runEngine = func(context.Context, engine.Options, engine.Desired) (engine.Result, error) {
		ran++
		return engine.Result{}, nil
	}
	defer func() { runEngine = engine.Run }()
	l, err := lockfile.Acquire(pre)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"update", "--prefix", pre, "--detect-json", "testdata/none.json"},
		{"apply", "--host-dir", host, "--prefix", pre}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "another amc") {
			t.Errorf("%v: exit %d, stderr %q", args[0], code, errb.String())
		}
	}
	if ran != 0 {
		t.Error("the engine ran while the lock was held")
	}
	l.Release()
	var out, errb bytes.Buffer
	if code := run([]string{"apply", "--host-dir", host, "--prefix", pre}, &out, &errb); code != exitOK || ran != 1 {
		t.Errorf("after release: exit %d, stderr %q", code, errb.String())
	}
}
