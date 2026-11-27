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

// plan / apply without --site-dir keep the owner's installed overlays (like the allowlist since v0.22.5); "none"
// removes them; a given directory wins; the control plane's cp-* files are not counted as the owner's
func TestSiteForKeepsTheInstalledOverlays(t *testing.T) {
	prefix := t.TempDir()
	site := filepath.Join(prefix, "config", "site.d")
	var out bytes.Buffer
	if d, kept := siteFor(&out, "", prefix); d != "" || kept {
		t.Fatalf("nothing installed: %q %v", d, kept)
	}
	if err := os.MkdirAll(site, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(site, generate.SitePrefix+"noise.yaml"), []byte("processors: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if d, kept := siteFor(&out, "", prefix); d != "" || kept {
		t.Fatalf("only control-plane files: not the owner's: %q %v", d, kept)
	}
	if err := os.WriteFile(filepath.Join(site, "filter.yaml"), []byte("processors: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if d, kept := siteFor(&out, "", prefix); d != site || !kept || !strings.Contains(out.String(), "filter.yaml") {
		t.Fatalf("installed overlays must be kept: %q %v %q", d, kept, out.String())
	}
	if d, _ := siteFor(&out, "none", prefix); d != "" {
		t.Fatalf("none removes them: %q", d)
	}
	if d, kept := siteFor(&out, "/x/site.d", prefix); d != "/x/site.d" || kept {
		t.Fatalf("a given directory wins: %q %v", d, kept)
	}
}

// v0.33.0: plan / apply / update read the control plane's service switches (switch on only) and the answers saved
// by apply stay the host owner's (the set is never merged into answers.yaml)
func TestAgentInputsWithTheServiceSwitches(t *testing.T) {
	prefix := t.TempDir()
	if err := os.MkdirAll(filepath.Join(prefix, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	ov, _ := generate.MarshalServicesOverlay(generate.ServicesOverlay{Revision: 4, Set: generate.ServicesSet{"redis": {On: true, Port: 6380}}})
	if err := os.WriteFile(filepath.Join(prefix, filepath.FromSlash(generate.ServicesFile)), ov, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, on := range []bool{false, true} {
		var h generate.Host
		var out bytes.Buffer
		a := generate.Answers{Agent: &generate.Agent{ServicesEdit: generate.AgentServicesEdit{Allow: on}}}
		if _, err := agentInputs(&out, &h, a, inputs{prefix: prefix}); err != nil {
			t.Fatal(err)
		}
		if got := h.ServicesCP.String(); (on && got != "redis on :6380") || (!on && got != "") {
			t.Errorf("switch %v: %q", on, got)
		}
		if on != strings.Contains(out.String(), "service switches (config/services.cp.yaml, revision 4): redis on :6380") {
			t.Errorf("switch %v: %s", on, out.String())
		}
		if a.Services != nil {
			t.Errorf("the answers were changed: %+v", a.Services)
		}
	}
}

// v0.35.0: plan / apply / update read the control plane's settings (within agent.settings.allow, answers win): the
// engine gets the effective switches (units), the answers saved by apply stay the host owner's
func TestBuildWithTheControlPlaneSettings(t *testing.T) {
	prefix := t.TempDir()
	if err := os.MkdirAll(filepath.Join(prefix, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	ov, _ := generate.MarshalSettingsOverlay(generate.SettingsOverlay{Revision: 2, Set: generate.SettingsSet{"rescan": true, "disk_scan": true}})
	if err := os.WriteFile(filepath.Join(prefix, filepath.FromSlash(generate.SettingsFile)), ov, 0o644); err != nil {
		t.Fatal(err)
	}
	ans := filepath.Join(t.TempDir(), "answers.yaml")
	body := "agent:\n  url: https://agent.example.com/agent/\n  control_plane_key: \"ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\n" +
		"  disk_scan:\n    allow: false\n  settings:\n    allow: [rescan, disk_scan]\n"
	if err := os.WriteFile(ans, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := generate.LoadAnswers(ans)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	d, err := build(&out, generate.Host{}, a, "", inputs{prefix: prefix})
	if err != nil {
		t.Fatal(err)
	}
	if d.Agent == nil || !d.Agent.Rescan || d.Agent.DiskScan {
		t.Errorf("engine switches: %+v (rescan from the set, disk_scan pinned off)", d.Agent)
	}
	if !strings.Contains(out.String(), "the control plane's settings (config/settings.cp.yaml, revision 2): disk_scan on, rescan on") {
		t.Errorf("plan output: %s", out.String())
	}
	if strings.Contains(string(d.Answers), "rescan:") || !strings.Contains(string(d.Answers), "disk_scan:\n    allow: false") {
		t.Errorf("saved answers are not the owner's:\n%s", d.Answers)
	}
	if a.Agent.Rescan.Allow {
		t.Error("the caller's answers were changed")
	}
}

// v0.36.0: the groups' values reach the generated configuration; an installed set the answers make invalid stops
// the plan with a clear reason (the console sends a new set, or the owner removes the file)
func TestBuildWithTheControlPlaneValues(t *testing.T) {
	prefix := t.TempDir()
	if err := os.MkdirAll(filepath.Join(prefix, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(o *generate.OracleValue) {
		ov, _ := generate.MarshalSettingsOverlay(generate.SettingsOverlay{Revision: 3, Set: generate.SettingsSet{},
			Values: &generate.SettingsValues{Checks: &generate.ChecksValue{HTTP: []generate.HTTPCheck{{URL: "https://app.example.com/health"}}}, Oracle: o}})
		if err := os.WriteFile(filepath.Join(prefix, filepath.FromSlash(generate.SettingsFile)), ov, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(nil)
	ans := filepath.Join(t.TempDir(), "answers.yaml")
	body := "agent:\n  url: https://agent.example.com/agent/\n  control_plane_key: \"ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\n" +
		"  settings:\n    allow: [checks, oracle]\nservices:\n  oracle:\n    non_cdb: true\n"
	if err := os.WriteFile(ans, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := generate.LoadAnswers(ans)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	d, err := build(&out, generate.Host{}, a, "", inputs{prefix: prefix})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(d.HostYAML)+string(d.HostEnv), "https://app.example.com/health") {
		t.Errorf("the check is not in the generated configuration:\n%s\n%s", d.HostYAML, d.HostEnv)
	}
	if !strings.Contains(out.String(), "revision 3): values of checks") || strings.Contains(string(d.Answers), "app.example.com") {
		t.Errorf("plan output / saved answers:\n%s\n%s", out.String(), d.Answers)
	}
	write(&generate.OracleValue{Service: "ORCL", User: "C##MON"})
	if _, err := build(&out, generate.Host{}, a, "", inputs{prefix: prefix}); err == nil || !strings.Contains(err.Error(), "non_cdb with a common user") {
		t.Errorf("invalid effective answers: %v", err)
	}
}
