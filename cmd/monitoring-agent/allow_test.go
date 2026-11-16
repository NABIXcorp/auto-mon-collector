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

// v0.26.0: plan / apply / update use the effective allowlist incl. the control plane's overlay (switch on, clamped):
// ping from the overlay renders CAP_NET_RAW into the prober unit like ping from the answers
func TestAgentInputsWithTheOverlay(t *testing.T) {
	prefix := t.TempDir()
	if err := os.MkdirAll(filepath.Join(prefix, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	ov, _ := generate.MarshalAllowOverlay(generate.Allow{Networks: []string{"192.0.2.0/24"}, MaxProbes: 90, Ping: true}, 3)
	if err := os.WriteFile(filepath.Join(prefix, filepath.FromSlash(generate.AllowOverlayFile)), ov, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		edit generate.AgentAllowEdit
		want string
	}{
		{generate.AgentAllowEdit{}, "networks -; ports 443; max 30 probes; interval >= 15 s; ping false"},
		{generate.AgentAllowEdit{Allow: true, MaxProbes: 60}, "networks 192.0.2.0/24; ports 443; max 60 probes; interval >= 15 s; ping false"},
		{generate.AgentAllowEdit{Allow: true, Ping: true, MaxProbes: 60}, "networks 192.0.2.0/24; ports 443; max 60 probes; interval >= 15 s; ping true"},
	} {
		var h generate.Host
		var out bytes.Buffer
		a := generate.Answers{Agent: &generate.Agent{Allow: generate.Allow{Ports: []int{443}}, AllowEdit: c.edit}}
		if _, err := agentInputs(&out, &h, a, inputs{prefix: prefix}); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(h.AgentAllow.String(), c.want) {
			t.Errorf("%+v: %s", c.edit, h.AgentAllow)
		}
	}
}
