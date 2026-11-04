package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/internal/cloudprober"
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
	r := &fakeRunner{readable: true}
	res, out := runWith(t, h, r, false, false, true, false, withAgent(t, h, true))
	if res.Failures != 0 {
		t.Fatalf("check failed:\n%s", out)
	}
	for _, want := range []string{"would: useradd --system --user-group --no-create-home --home-dir /opt/monitoring/agent",
		"4c. agent: binary + polkit rule", "would: install /opt/monitoring/bin/monitoring-agent", "would: write " + PolkitRule,
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
	r := &fakeRunner{readable: true}
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
	r := &fakeRunner{readable: true}
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
		!strings.Contains(u, "ReadWritePaths=/opt/monitoring/agent /opt/monitoring/config/prober") {
		t.Errorf("agent unit:\n%s", u)
	}
	if rule := h.read(PolkitRule); !strings.Contains(rule, `"monitoring-prober.service"`) || !strings.Contains(rule, `"restart"`) {
		t.Errorf("polkit rule:\n%s", rule)
	}
	fi, err := os.Stat(filepath.Join(h.root, "opt/monitoring/config/prober"))
	if err != nil || fi.Mode()&os.ModeSetgid == 0 || fi.Mode().Perm() != 0o775 {
		t.Errorf("config/prober mode: %v %v", fi.Mode(), err)
	}
	// v0.16.0: the self-update unit is written and linked, but never enabled, restarted or checked
	if u := h.read("/opt/monitoring/systemd/monitoring-update.service"); !strings.Contains(u, "Type=oneshot") {
		t.Errorf("update unit:\n%s", u)
	}
	if l, err := os.Readlink(filepath.Join(h.root, "etc/systemd/system/monitoring-update.service")); err != nil ||
		l != "/opt/monitoring/systemd/monitoring-update.service" {
		t.Errorf("update unit link: %q %v", l, err)
	}
	for _, c := range r.cmds {
		if strings.Contains(c, "monitoring-update") {
			t.Errorf("apply ran a command on the update unit: %s", c)
		}
	}
	if rule := h.read(PolkitRule); !strings.Contains(rule, `"monitoring-update.service"`) || !strings.Contains(rule, `"start"`) {
		t.Errorf("polkit rule:\n%s", rule)
	}
	st := h.read("/opt/monitoring/" + StateFile)
	for _, want := range []string{"monitoring-agent.service", "monitoring-update.service", PolkitRule} {
		if !strings.Contains(st, want) {
			t.Errorf("state lacks %s:\n%s", want, st)
		}
	}
	// a plan right after: nothing to do
	r1 := &fakeRunner{readable: true, probeVersion: "v" + cloudprober.Version}
	_, out = runWith(t, h, r1, false, false, false, false, withAgent(t, h, true))
	for _, bad := range []string{"CHANGE ", "NEW    ", "REMOVE ", "would: install /opt/monitoring/bin/monitoring-agent", "would: write " + PolkitRule, "would: chmod"} {
		if strings.Contains(out, bad) {
			t.Errorf("plan after apply not clean (%q):\n%s", bad, out)
		}
	}

	// agent removed from the answers: unit stopped + unlinked, its files and the polkit rule gone
	r2 := &fakeRunner{readable: true, probeVersion: "v" + cloudprober.Version}
	res, out = runWith(t, h, r2, true, true, false, false, withProbes(false))
	if res.Failures != 0 {
		t.Fatalf("second apply failed:\n%s", out)
	}
	for _, want := range []string{"REMOVE systemd/monitoring-agent.service", "REMOVE systemd/monitoring-update.service",
		"no agent: monitoring-update.service unlinked", "REMOVE config/agent-allow.yaml",
		"no agent: monitoring-agent.service stopped, disabled and unlinked", "no agent: " + PolkitRule + " removed"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(h.root, filepath.FromSlash(PolkitRule))); err == nil {
		t.Error("polkit rule left")
	}
	if _, err := os.Lstat(filepath.Join(h.root, "etc/systemd/system/monitoring-update.service")); err == nil {
		t.Error("update unit link left")
	}
	if strings.Contains(h.read("/opt/monitoring/"+StateFile), "monitoring-update") {
		t.Error("update unit still in the state")
	}
	fi, _ = os.Stat(filepath.Join(h.root, "opt/monitoring/config/prober"))
	if fi.Mode()&os.ModeSetgid != 0 || fi.Mode().Perm() != 0o755 {
		t.Errorf("config/prober not root-only again: %v", fi.Mode())
	}
}

func TestUninstallRemovesTheAgent(t *testing.T) {
	needSymlinks(t)
	h := agentHost(t)
	h.write("/etc/passwd", "root:x:0:0::/root:/bin/bash\notelcol-contrib:x:990:990::/opt/monitoring/data:/sbin/nologin\n", 0o644)
	r := &fakeRunner{readable: true}
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
	for _, c := range ru.cmds {
		if strings.HasPrefix(c, "systemctl disable") && strings.Contains(c, "monitoring-update") {
			t.Errorf("never enabled, so not disabled: %s", c)
		}
	}
	for _, gone := range []string{"opt/monitoring/agent", filepath.FromSlash(PolkitRule)[1:], "etc/systemd/system/monitoring-agent.service",
		"etc/systemd/system/monitoring-update.service"} {
		if _, err := os.Lstat(filepath.Join(h.root, gone)); err == nil {
			t.Errorf("%s still there", gone)
		}
	}
}

// v019Host: a v0.19.0 host with agent + probes: bin/amc, bin/cloudprober, config/cloudprober/, unit
// monitoring-cloudprober, polkit 50-amc-agent.rules, amc-state.json (all renamed in v0.20.0).
func v019Host(t *testing.T) host {
	h := agentHost(t)
	h.write("/opt/monitoring/bin/amc", "OLD-AMC", 0o755)
	h.write("/opt/monitoring/bin/cloudprober", "OLD-PROBER", 0o755)
	h.write("/opt/monitoring/config/config.yaml", "old config\n", 0o644)
	h.write("/opt/monitoring/config/cloudprober/cloudprober.cfg", "old cfg\n", 0o644)
	h.write("/opt/monitoring/config/cloudprober/cloudprober-tcp.json", "{}\n", 0o644)
	h.write("/opt/monitoring/systemd/monitoring-cloudprober.service", "old prober unit\n", 0o644)
	h.write("/etc/polkit-1/rules.d/50-amc-agent.rules", "old rule\n", 0o644)
	h.write("/opt/monitoring/amc-state.json", `{"version":1,"prefix":"/opt/monitoring","user":"otelcol-contrib","units":["monitoring-cloudprober.service"],"polkit_rules":["/etc/polkit-1/rules.d/50-amc-agent.rules"]}`+"\n", 0o644)
	link := filepath.Join(h.root, "etc/systemd/system/monitoring-cloudprober.service")
	os.MkdirAll(filepath.Dir(link), 0o755)
	if err := os.Symlink("/opt/monitoring/systemd/monitoring-cloudprober.service", link); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestRenameToMonitoringNames(t *testing.T) {
	needSymlinks(t)
	h := v019Host(t)
	r := &fakeRunner{readable: true}
	res, out := runWith(t, h, r, true, true, true, false, withAgent(t, h, false))
	if res.Failures != 0 || res.RolledBack {
		t.Fatalf("apply failed:\n%s", out)
	}
	if h.read("/opt/monitoring/bin/monitoring-agent") != "AMC-BINARY" || h.read("/opt/monitoring/bin/amc.previous") != "OLD-AMC" {
		t.Errorf("agent binary not installed / old one not kept:\n%s", out)
	}
	if l, err := os.Readlink(filepath.Join(h.root, "opt/monitoring/bin/amc")); err != nil || l != "monitoring-agent" {
		t.Errorf("bin/amc = %q %v, want a symlink to monitoring-agent", l, err)
	}
	if h.read("/opt/monitoring/bin/monitoring-prober") != "PROBER" || h.read("/opt/monitoring/config/prober/targets-tcp.json") == "" {
		t.Errorf("prober not installed under the new names:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(h.root, "opt/monitoring/config/cloudprober")); err == nil {
		t.Errorf("config/cloudprober left:\n%s", out)
	}
	if linked(h, "monitoring-cloudprober.service") || !linked(h, "monitoring-prober.service") || !r.has("systemctl disable --now monitoring-cloudprober.service") {
		t.Errorf("prober unit not switched: %v", r.cmds)
	}
	if h.read("/etc/polkit-1/rules.d/50-monitoring-agent.rules") == "" || h.read("/etc/polkit-1/rules.d/50-amc-agent.rules.previous") != "old rule\n" {
		t.Error("polkit rule not renamed (old one kept as .previous)")
	}
	if _, err := os.Stat(filepath.Join(h.root, "etc/polkit-1/rules.d/50-amc-agent.rules")); err == nil {
		t.Error("old polkit rule still active")
	}
	st := h.read("/opt/monitoring/state.json")
	if _, err := os.Stat(filepath.Join(h.root, "opt/monitoring/amc-state.json")); err == nil ||
		strings.Contains(st, "50-amc-agent") || !strings.Contains(st, "50-monitoring-agent") || strings.Contains(st, "monitoring-cloudprober") {
		t.Errorf("state not moved / updated: %s", st)
	}
}

func TestRenameRollbackBringsTheOldNamesBack(t *testing.T) {
	needSymlinks(t)
	h := v019Host(t)
	r := &fakeRunner{readable: true, inactive: 1}
	res, out := runWith(t, h, r, true, true, true, false, withAgent(t, h, false))
	if !res.RolledBack {
		t.Fatalf("want a rollback:\n%s", out)
	}
	if h.read("/opt/monitoring/bin/amc") != "OLD-AMC" || h.read("/etc/polkit-1/rules.d/50-amc-agent.rules") != "old rule\n" ||
		h.read("/opt/monitoring/config/cloudprober/cloudprober.cfg") != "old cfg\n" {
		t.Errorf("old binary / polkit rule / prober config not back:\n%s", out)
	}
	if !linked(h, "monitoring-cloudprober.service") || linked(h, "monitoring-prober.service") {
		t.Errorf("old prober unit not linked again:\n%s", out)
	}
}
