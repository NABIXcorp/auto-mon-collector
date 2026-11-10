package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

// v0.22.5: plan / apply without --agent-allow keep the installed template; "none" removes it; a file wins.
func TestAllowForKeepsTheInstalledTemplate(t *testing.T) {
	prefix := t.TempDir()
	installed := filepath.Join(prefix, filepath.FromSlash(generate.AllowFile))
	withAgent := generate.Answers{Agent: &generate.Agent{}}
	var out bytes.Buffer
	if got := allowFor(&out, "", prefix, withAgent); got != "" {
		t.Fatalf("nothing installed: %q", got)
	}
	if err := os.MkdirAll(filepath.Dir(installed), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installed, []byte("domains: [example.org]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := allowFor(&out, "", prefix, withAgent); got != installed || !strings.Contains(out.String(), "is kept") {
		t.Fatalf("installed template must be kept: %q %q", got, out.String())
	}
	if got := allowFor(&out, "none", prefix, withAgent); got != "" {
		t.Fatalf("none removes it: %q", got)
	}
	if got := allowFor(&out, "/x/allow.yaml", prefix, withAgent); got != "/x/allow.yaml" {
		t.Fatalf("a given file wins: %q", got)
	}
	if got := allowFor(&out, "", prefix, generate.Answers{}); got != "" {
		t.Fatalf("no agent section: no template: %q", got)
	}
}
