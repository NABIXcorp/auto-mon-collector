package assets

import (
	"bytes"
	"strings"
	"testing"
)

func TestAssetsPresentAndLF(t *testing.T) {
	for name, b := range map[string][]byte{"config": BaseConfig(), "netconn": Netconn()} {
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
