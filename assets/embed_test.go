package assets

import (
	"bytes"
	"strings"
	"testing"
)

func TestAssetsPresentAndLF(t *testing.T) {
	for name, b := range map[string][]byte{"config": BaseConfig(), "netconn": Netconn(), "kmsg": Kmsg(), "procs": Procs()} {
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
	b, _ := Unit("monitoring-otelcol", UnitData{Prefix: "/opt/monitoring", User: "u",
		SiteConfigs: []string{"/x/a.yaml", "/x/b.yaml"}})
	if !strings.Contains(string(b), "--config=/x/a.yaml --config=/x/b.yaml\n") {
		t.Errorf("site configs not appended to ExecStart:\n%s", b)
	}
}

// Privacy (v0.6.0): the process helper writes command names only (ps comm), never arguments (they can hold
// passwords), and runs without network or capabilities.
func TestProcsWritesNoArguments(t *testing.T) {
	s := string(Procs())
	if !strings.Contains(s, "comm=") || strings.Contains(s, "args") || strings.Contains(s, "cmd=") || strings.Contains(s, "command=") {
		t.Error("otel-procs.sh must use ps comm only (no args / cmd / command columns)")
	}
	u, _ := Unit("monitoring-procs", UnitData{Prefix: "/opt/monitoring", User: "otelcol-contrib"})
	for _, want := range []string{"PrivateNetwork=yes", "NoNewPrivileges=yes", "CapabilityBoundingSet=\n",
		"ReadWritePaths=/opt/monitoring/data/procs\n"} {
		if !strings.Contains(string(u), want) {
			t.Errorf("monitoring-procs lacks %q", want)
		}
	}
}

// Privacy (v0.7.0): the SSH helper reads sshd's own messages only and masks unknown user names (often a password
// typed into the user field) before writing. The real masking is tested end to end in CI with logger.
func TestSshdReadsSshdOnlyAndMasks(t *testing.T) {
	s := string(Sshd())
	for _, want := range []string{"journalctl -t sshd -t sshd-session", "--after-cursor", `([Ii]nvalid user) ([^ ]+ )?(from )/\1 *** \3/`} {
		if !strings.Contains(s, want) {
			t.Errorf("otel-sshd.sh lacks %q", want)
		}
	}
	if strings.Contains(s, "sudo") && !strings.Contains(s, "Never sudo") {
		t.Error("otel-sshd.sh must not read sudo")
	}
}

// Least privilege (v0.5.0): only the kernel-messages helper may read the journal, and it reads kernel messages
// only (-k, priority warning+, no history); the collector unit never gets the journal group.
func TestJournalAccessOnlyForKmsg(t *testing.T) {
	for _, u := range UnitNames {
		b, _ := Unit(u, UnitData{Prefix: "/opt/monitoring", User: "otelcol-contrib"})
		has := strings.Contains(string(b), "systemd-journal")
		if has != (u == "monitoring-kmsg" || u == "monitoring-sshd") { // the two journal readers, never the collector
			t.Errorf("%s: systemd-journal group = %v", u, has)
		}
	}
	k, _ := Unit("monitoring-kmsg", UnitData{Prefix: "/opt/monitoring", User: "otelcol-contrib"})
	for _, want := range []string{"NoNewPrivileges=yes", "PrivateNetwork=yes", "ProtectSystem=strict",
		"ReadWritePaths=/opt/monitoring/data/kmsg\n", "CapabilityBoundingSet=\n"} {
		if !strings.Contains(string(k), want) {
			t.Errorf("monitoring-kmsg lacks %q", want)
		}
	}
	s := string(Kmsg())
	for _, want := range []string{"journalctl -k -p warning", "--after-cursor", "--output-fields=MESSAGE,PRIORITY"} {
		if !strings.Contains(s, want) {
			t.Errorf("otel-kmsg.sh lacks %q", want)
		}
	}
}
