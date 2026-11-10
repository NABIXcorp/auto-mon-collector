package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v0.23.0: plan / apply keep the control plane's installed overlays and refuse cp-* files in --site-dir
func TestKeepControlPlaneSite(t *testing.T) {
	pre := t.TempDir()
	sd := filepath.Join(pre, "config", "site.d")
	if err := os.MkdirAll(sd, 0o755); err != nil {
		t.Fatal(err)
	}
	for n, s := range map[string]string{"cp-noise.yaml": "processors: {}\n", "10-old.yaml": "x: 1\n"} {
		if err := os.WriteFile(filepath.Join(sd, n), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := keepControlPlaneSite(io.Discard, map[string][]byte{"10-new.yaml": []byte("y: 2\n")}, pre)
	if err != nil || len(got) != 2 || string(got["cp-noise.yaml"]) != "processors: {}\n" || got["10-old.yaml"] != nil {
		t.Fatalf("kept: %v %v", got, err)
	}
	if got, err := keepControlPlaneSite(io.Discard, nil, pre); err != nil || len(got) != 1 {
		t.Fatalf("no --site-dir: %v %v", got, err)
	}
	if _, err := keepControlPlaneSite(io.Discard, map[string][]byte{"cp-mine.yaml": nil}, pre); err == nil || !strings.Contains(err.Error(), "control plane") {
		t.Fatalf("a cp-* file in --site-dir: %v", err)
	}
}
