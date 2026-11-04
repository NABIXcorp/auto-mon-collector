package assets

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestAssetsPresentAndLF(t *testing.T) {
	for name, b := range map[string][]byte{"config": BaseConfig(), "journal": JournalConfig()} {
		if len(b) == 0 {
			t.Fatalf("%s is empty", name)
		}
		if bytes.Contains(b, []byte("\r")) {
			t.Errorf("%s has CR line endings", name)
		}
	}
}

func TestUnitRender(t *testing.T) {
	for _, u := range UnitNames {
		b, err := Unit(u, UnitData{Prefix: "/opt/monitoring", User: "otelcol-contrib",
			SiteConfigs: []string{"/opt/monitoring/config/site.d/10-site.yaml"}})
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		s := string(b)
		if strings.Contains(s, "{{") {
			t.Errorf("%s: unrendered template: %s", u, s)
		}
		if !strings.Contains(s, "User=otelcol-contrib") || !strings.Contains(s, "/opt/monitoring/") {
			t.Errorf("%s: prefix / user not applied", u)
		}
	}
	b, _ := Unit("monitoring-collector", UnitData{Prefix: "/opt/monitoring", User: "u",
		SiteConfigs: []string{"/x/a.yaml", "/x/b.yaml"}})
	want := "ExecStart=/opt/monitoring/bin/monitoring-collector --config=/opt/monitoring/config/config.yaml " +
		"--config=/opt/monitoring/config/journal.yaml --config=/opt/monitoring/config/host.yaml --config=/x/a.yaml --config=/x/b.yaml\n"
	if !strings.Contains(string(b), want) {
		t.Errorf("ExecStart: want %q in\n%s", want, b)
	}
}

// v0.19.0: the journal fragment amc installs is exactly the one collector/test/journal checks with golden files
// (fixed filters, MESSAGE only, unknown SSH user names masked).
func TestJournalConfigIsTheTestedOne(t *testing.T) {
	tested, err := os.ReadFile("../collector/config/journal.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(JournalConfig(), tested) {
		t.Fatal("assets/config/journal.yaml differs from collector/config/journal.yaml: copy it (cp collector/config/journal.yaml assets/config/)")
	}
}

// v0.19.0 (phase D2, accepted 2026-11-03): ONLY the collector unit gets the journal group (no other unit), and the
// ssh pipeline masks before anything else touches a record.
func TestJournalAccessOnlyForTheCollector(t *testing.T) {
	for _, u := range append(append([]string{}, UnitNames...), ProbeUnit, AgentUnit, UpdateUnit) {
		b, err := Unit(u, UnitData{Prefix: "/opt/monitoring", User: "otelcol-contrib"})
		if err != nil {
			t.Fatal(err)
		}
		if has := strings.Contains(string(b), "SupplementaryGroups=systemd-journal"); has != (u == "monitoring-collector") {
			t.Errorf("%s: systemd-journal group = %v", u, has)
		}
	}
	c := string(BaseConfig())
	if !strings.Contains(c, "receivers: [journald/sshd]\n      processors: [transform/sshd, resource_detection, batch]") {
		t.Error("config.yaml: logs/ssh must read journald/sshd with transform/sshd as its FIRST processor")
	}
	for _, old := range []string{"file_log/netconn", "file_log/kmsg", "file_log/procs", "file_log/sshd"} {
		if strings.Contains(c, old) {
			t.Errorf("config.yaml still has %s (helper files are gone since v0.19.0)", old)
		}
	}
}

// Cloudprober (v0.12.0): CAP_NET_RAW only with ping probes, metrics on 127.0.0.1 only (in its config).
func TestProbeUnitCapabilityOnlyForPing(t *testing.T) {
	for _, ping := range []bool{false, true} {
		b, err := Unit(ProbeUnit, UnitData{Prefix: "/opt/monitoring", User: "otelcol-contrib", Ping: ping})
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		if got := strings.Contains(s, "AmbientCapabilities=CAP_NET_RAW"); got != ping {
			t.Errorf("ping=%v: AmbientCapabilities present=%v\n%s", ping, got, s)
		}
		if !ping && !strings.Contains(s, "CapabilityBoundingSet=\n") {
			t.Errorf("no ping: capabilities must be empty\n%s", s)
		}
		if !strings.Contains(s, "--config_file=/opt/monitoring/config/prober/prober.cfg") || !strings.Contains(s, "NoNewPrivileges=yes") ||
			!strings.Contains(s, "User=otelcol-contrib") {
			t.Errorf("unit:\n%s", s)
		}
	}
}

// Agent (v0.13.0): not root, no capabilities, writes only its dir and the Cloudprober files; the polkit rule allows
// only restarting the Cloudprober unit.
func TestAgentUnitAndPolkitRule(t *testing.T) {
	b, err := Unit(AgentUnit, UnitData{Prefix: "/opt/monitoring", User: "otelcol-contrib"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"User=amc-agent", "NoNewPrivileges=yes", "ProtectSystem=strict", "CapabilityBoundingSet=\n",
		"ReadWritePaths=/opt/monitoring/agent /opt/monitoring/config/prober\n", "ExecStart=/opt/monitoring/bin/monitoring-agent agent run --prefix /opt/monitoring"} {
		if !strings.Contains(s, want) {
			t.Errorf("agent unit lacks %q:\n%s", want, s)
		}
	}
	r := string(AgentPolkit())
	for _, want := range []string{`subject.user == "amc-agent"`, `action.lookup("unit") == "monitoring-prober.service"`,
		`action.lookup("verb") == "restart"`, `"org.freedesktop.systemd1.manage-units"`,
		// v0.16.0: start (only) of the self-update unit
		"action.lookup(\"unit\") == \"monitoring-update.service\" &&\n        action.lookup(\"verb\") == \"start\")"} {
		if !strings.Contains(r, want) {
			t.Errorf("polkit rule lacks %q:\n%s", want, r)
		}
	}
	if strings.Count(r, "polkit.Result.YES") != 2 || strings.Count(r, `subject.user == "amc-agent"`) != 2 {
		t.Errorf("polkit rule: every YES must be bound to amc-agent, one unit and one verb:\n%s", r)
	}
}

// Self-update unit (v0.16.0): root oneshot, started on demand only (no [Install]: never enabled), fixed arguments.
func TestUpdateUnit(t *testing.T) {
	b, err := Unit(UpdateUnit, UnitData{Prefix: "/opt/monitoring", User: "otelcol-contrib"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"Type=oneshot\n", "User=root\n", "NoNewPrivileges=yes\n", "PrivateTmp=yes\n", "TimeoutStartSec=15min\n",
		"ExecStart=/opt/monitoring/bin/monitoring-agent self-update --prefix /opt/monitoring --request /opt/monitoring/agent/update-request.json\n"} {
		if !strings.Contains(s, want) {
			t.Errorf("update unit lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "[Install]") || strings.Contains(s, "{{") {
		t.Errorf("update unit must have no [Install] section:\n%s", s)
	}
}
