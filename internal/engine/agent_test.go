package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/internal/cloudprober"
	"github.com/NABIXcorp/auto-mon-collector/internal/collector"
)

func withAgent(t *testing.T, h host, template bool) Desired {
	d := withProbes(false)
	bin := filepath.Join(t.TempDir(), "amc")
	if err := os.WriteFile(bin, []byte("AMC-BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}
	d.Agent = &Agent{Binary: bin}
	if template {
		d.Agent.AllowTemplate = []byte("domains: [\"*.example.com\"]\n")
	}
	h.write("/etc/polkit-1/rules.d/.keep", "", 0o644)
	return d
}

func agentHost(t *testing.T) host {
	h := smokeHost(t)
	h.write("/etc/passwd", h.read("/etc/passwd")+"amc-agent:x:989:989::/opt/monitoring/agent:/sbin/nologin\n", 0o644)
	return h
}

func TestAgentCheckMode(t *testing.T) {
	h := smokeHost(t) // no amc-agent user yet
	r := &fakeRunner{version: collector.Version, readable: true}
	res, out := runWith(t, h, r, false, false, true, false, withAgent(t, h, true))
	if res.Failures != 0 {
		t.Fatalf("check failed:\n%s", out)
	}
	for _, want := range []string{"would: useradd --system --user-group --no-create-home --home-dir /opt/monitoring/agent",
		"4c. agent: binary + polkit rule", "would: install /opt/monitoring/bin/amc", "would: write " + PolkitRule,
		"NEW    systemd/monitoring-agent.service", "NEW    config/agent-allow.yaml"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, c := range r.cmds {
		if strings.Contains(c, "validate") && strings.Contains(c, "agent-allow") {
			t.Errorf("the allowlist template was given to otelcol validate: %s", c)
		}
	}
	if _, err := os.Stat(filepath.Join(h.root, filepath.FromSlash(PolkitRule))); err == nil {
		t.Error("check mode wrote the polkit rule")
	}
}

func TestAgentWithoutPolkitWarns(t *testing.T) {
	h := agentHost(t)
	d := withAgent(t, h, false)
	os.RemoveAll(filepath.Join(h.root, "etc/polkit-1"))
	r := &fakeRunner{version: collector.Version, readable: true}
	res, out := runWith(t, h, r, false, false, true, false, d)
	if res.Warnings == 0 || !strings.Contains(out, "polkit not installed") {
		t.Errorf("missing polkit not reported:\n%s", out)
	}
}

func TestAgentApplyThenRemove(t *testing.T) {
	needSymlinks(t)
	h := agentHost(t)
	// a v0.12.0 host: Cloudprober files directly in config/
	h.write("/opt/monitoring/config/cloudprober.cfg", "old\n", 0o644)
	h.write("/opt/monitoring/config/cloudprober-tcp.json", "{}\n", 0o644)
	r := &fakeRunner{version: collector.Version, readable: true}
	res, out := runWith(t, h, r, true, true, true, false, withAgent(t, h, true))
	if res.Failures != 0 {
		t.Fatalf("apply failed:\n%s", out)
	}
	for _, want := range []string{"REMOVE config/cloudprober.cfg", "REMOVE config/cloudprober-tcp.json", "monitoring-agent.service active"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if h.read("/opt/monitoring/bin/amc") != "AMC-BINARY" {
		t.Error("bin/amc not installed")
	}
	if u := h.read("/opt/monitoring/systemd/monitoring-agent.service"); !strings.Contains(u, "User=amc-agent") ||
		!strings.Contains(u, "ReadWritePaths=/opt/monitoring/agent /opt/monitoring/config/cloudprober") {
		t.Errorf("agent unit:\n%s", u)
	}
	if rule := h.read(PolkitRule); !strings.Contains(rule, `"monitoring-cloudprober.service"`) || !strings.Contains(rule, `"restart"`) {
		t.Errorf("polkit rule:\n%s", rule)
	}
	fi, err := os.Stat(filepath.Join(h.root, "opt/monitoring/config/cloudprober"))
	if err != nil || fi.Mode()&os.ModeSetgid == 0 || fi.Mode().Perm() != 0o775 {
		t.Errorf("config/cloudprober mode: %v %v", fi.Mode(), err)
	}
	st := h.read("/opt/monitoring/" + StateFile)
	for _, want := range []string{"monitoring-agent.service", PolkitRule} {
		if !strings.Contains(st, want) {
			t.Errorf("state lacks %s:\n%s", want, st)
		}
	}
	// a plan right after: nothing to do
	r1 := &fakeRunner{version: collector.Version, readable: true, probeVersion: "v" + cloudprober.Version}
	_, out = runWith(t, h, r1, false, false, false, false, withAgent(t, h, true))
	for _, bad := range []string{"CHANGE ", "NEW    ", "REMOVE ", "would: install /opt/monitoring/bin/amc", "would: write " + PolkitRule, "would: chmod"} {
		if strings.Contains(out, bad) {
			t.Errorf("plan after apply not clean (%q):\n%s", bad, out)
		}
	}

	// agent removed from the answers: unit stopped + unlinked, its files and the polkit rule gone
	r2 := &fakeRunner{version: collector.Version, readable: true, probeVersion: "v" + cloudprober.Version}
	res, out = runWith(t, h, r2, true, true, false, false, withProbes(false))
	if res.Failures != 0 {
		t.Fatalf("second apply failed:\n%s", out)
	}
	for _, want := range []string{"REMOVE systemd/monitoring-agent.service", "REMOVE config/agent-allow.yaml",
		"no agent: monitoring-agent.service stopped, disabled and unlinked", "no agent: " + PolkitRule + " removed"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(h.root, filepath.FromSlash(PolkitRule))); err == nil {
		t.Error("polkit rule left")
	}
	fi, _ = os.Stat(filepath.Join(h.root, "opt/monitoring/config/cloudprober"))
	if fi.Mode()&os.ModeSetgid != 0 || fi.Mode().Perm() != 0o755 {
		t.Errorf("config/cloudprober not root-only again: %v", fi.Mode())
	}
}

func TestUninstallRemovesTheAgent(t *testing.T) {
	needSymlinks(t)
	h := agentHost(t)
	h.write("/etc/passwd", "root:x:0:0::/root:/bin/bash\notelcol-contrib:x:990:990::/opt/monitoring/data:/sbin/nologin\n", 0o644)
	r := &fakeRunner{version: collector.Version, readable: true}
	if res, out := runWith(t, h, r, true, false, true, false, withAgent(t, h, false)); res.Failures != 0 {
		t.Fatalf("apply: %s", out)
	}
	if !strings.Contains(h.read("/opt/monitoring/"+StateFile), `"agent_user_created": true`) {
		t.Fatalf("agent user not recorded:\n%s", h.read("/opt/monitoring/"+StateFile))
	}
	h.write("/opt/monitoring/agent/key", "SECRET\n", 0o600)
	ru := &fakeRunner{}
	res, out := uninstallRun(t, h, ru, true, UninstallOptions{})
	if res.Failures != 0 {
		t.Fatalf("%s", out)
	}
	if !ru.has("userdel amc-agent") {
		t.Errorf("agent user not removed: %v", ru.cmds)
	}
	for _, gone := range []string{"opt/monitoring/agent", filepath.FromSlash(PolkitRule)[1:], "etc/systemd/system/monitoring-agent.service"} {
		if _, err := os.Lstat(filepath.Join(h.root, gone)); err == nil {
			t.Errorf("%s still there", gone)
		}
	}
}
