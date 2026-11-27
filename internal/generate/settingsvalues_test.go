package generate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const groupsOn = "  settings:\n    allow: [checks, oracle, tomcat, rescan]\n"

func valuesJSON(t *testing.T, s string) *SettingsValues {
	t.Helper()
	var v SettingsValues
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func TestSettingsGroupsConsent(t *testing.T) {
	got, err := ParseSettingsAllow("tomcat,checks, oracle ,rescan")
	if err != nil || strings.Join(got, ",") != "checks,oracle,rescan,tomcat" {
		t.Fatalf("parse: %q %v", got, err)
	}
	if _, err := ParseSettingsAllow("checks,postgres"); err == nil || !strings.Contains(err.Error(), `unknown key "postgres"`) {
		t.Errorf("unknown group: %v", err)
	}
	// a switch set naming a group is not a switch
	if err := CheckSettingsSet(SettingsSet{"checks": true}, settingsAnswers(t, groupsOn).Agent); err == nil || !strings.Contains(err.Error(), `unknown key "checks"`) {
		t.Errorf("group as a switch: %v", err)
	}
}

// a group is pinned when the answers write one of its fields with a value; the pin survives a rewrite of the answers
func TestSettingsGroupPins(t *testing.T) {
	a := settingsAnswers(t, groupsOn+"checks:\n  tcp:\n    - endpoint: db.example.com:1521\nservices:\n  oracle:\n    non_cdb: true\n  tomcat:\n    time_zone: UTC\n")
	if got := strings.Join(a.Agent.Pinned(), ","); got != "checks,tomcat" {
		t.Errorf("pinned: %q (oracle writes only non_cdb: outside the group)", got)
	}
	b, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "answers.yaml")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	again, err := LoadAnswers(p)
	if err != nil || strings.Join(again.Agent.Pinned(), ",") != "checks,tomcat" {
		t.Errorf("after a rewrite: %v %q", err, again.Agent.Pinned())
	}
	// the effective copy keeps the answers' pins, also after values were applied
	eff := ApplySettings(a, SettingsOverlay{Values: valuesJSON(t, `{"oracle":{"service":"pdb1","user":"mon","capacity":false,"capacity_pdbs":[]}}`)})
	if got := strings.Join(eff.Agent.Pinned(), ","); got != "checks,tomcat" {
		t.Errorf("effective pins: %q", got)
	}
}

func TestCheckSettingsValues(t *testing.T) {
	a := settingsAnswers(t, groupsOn+"services:\n  tomcat:\n    login_path: ^/app/login\n  oracle:\n    non_cdb: true\n")
	cases := []struct {
		name, values string
		want         string // "" = accepted
	}{
		{"checks", `{"checks":{"http":[{"url":"https://app.example.com/health","comment":"app"}],"tcp":[{"endpoint":"db.example.com:1521","comment":""}]}}`, ""},
		{"empty checks = none", `{"checks":{"http":[],"tcp":[]}}`, ""},
		{"oracle", `{"oracle":{"service":"ORCL","user":"otel_mon","capacity":true,"capacity_pdbs":[]}}`, ""},
		{"null = not managed", `{"oracle":null}`, ""},
		{"unknown group", `{"checks":{"http":[],"tcp":[]},"postgres":{"user":"x"}}`, "postgres: unknown group"},
		{"unknown field in a group", `{"oracle":{"service":"PDB1","password":"x"}}`, `unknown field "password"`},
		{"pinned group", `{"tomcat":{"logs":[],"time_zone":"","login_path":""}}`, "tomcat is pinned"},
		{"bad url", `{"checks":{"http":[{"url":"ftp://x.example.com/"}],"tcp":[]}}`, "is not an http(s) URL"},
		{"credentials in a url", `{"checks":{"http":[{"url":"https://u:p@x.example.com/"}],"tcp":[]}}`, "contains credentials"},
		{"loopback tcp", `{"checks":{"http":[],"tcp":[{"endpoint":"127.0.0.1:6379"}]}}`, "loopback"},
		// non_cdb (outside the group, from the answers) excludes a common user: the effective answers are checked
		{"common user with the answers' non_cdb", `{"oracle":{"service":"PDB1","user":"C##MON","capacity":false,"capacity_pdbs":[]}}`, "non_cdb with a common user"},
		{"capacity_pdbs without capacity", `{"oracle":{"service":"PDB1","user":"mon","capacity":false,"capacity_pdbs":["PDB2"]}}`, "needs services.oracle.capacity: true"},
	}
	for _, c := range cases {
		ov := SettingsOverlay{Set: SettingsSet{"rescan": true}, Values: valuesJSON(t, c.values)}
		err := CheckSettings(ov, a)
		if (c.want == "" && err != nil) || (c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want))) {
			t.Errorf("%s: %v (want %q)", c.name, err, c.want)
		}
	}
	// a group outside the consent list
	b := settingsAnswers(t, "  settings:\n    allow: [rescan]\n")
	if err := CheckSettings(SettingsOverlay{Values: valuesJSON(t, `{"checks":{"http":[],"tcp":[]}}`)}, b); err == nil || !strings.Contains(err.Error(), "checks is not in answers.yaml agent.settings.allow") {
		t.Errorf("not consented: %v", err)
	}
	// a step-1 set (switches only) is still accepted; no consent at all is refused
	if err := CheckSettings(SettingsOverlay{Set: SettingsSet{"rescan": false}}, b); err != nil {
		t.Errorf("switches only: %v", err)
	}
	if err := CheckSettings(SettingsOverlay{Values: valuesJSON(t, `{}`)}, settingsAnswers(t, "")); err == nil {
		t.Error("no consent: accepted")
	}
}

func TestApplySettingsValues(t *testing.T) {
	a := settingsAnswers(t, "  settings:\n    allow: [checks, oracle]\nservices:\n  oracle:\n    non_cdb: true\n    data_guard: true\n")
	v := valuesJSON(t, `{"checks":{"http":[{"url":"https://a.example.com/"}],"tcp":[]},`+
		`"oracle":{"service":"ORCL","user":"otel","capacity":true,"capacity_pdbs":[]},`+
		`"tomcat":{"logs":["/opt/tomcat/logs/catalina.*.log"],"time_zone":"UTC","login_path":""}}`)
	eff := ApplySettings(a, SettingsOverlay{Values: v})
	o := eff.Services["oracle"]
	if len(eff.Checks.HTTP) != 1 || o.Service != "ORCL" || o.User != "otel" || !o.Capacity || !o.NonCDB || !o.DataGuard {
		t.Errorf("effective: %+v %+v", eff.Checks, o)
	}
	if _, ok := eff.Services["tomcat"]; ok {
		t.Error("tomcat applied without consent")
	}
	if a.Services["oracle"].Service != "" || len(a.Checks.HTTP) != 0 {
		t.Error("the answers were changed")
	}
	if err := eff.Validate(); err != nil {
		t.Error(err)
	}
	sv := SettingsValuesOf(eff)
	b, _ := json.Marshal(sv)
	want := `{"checks":{"http":[{"url":"https://a.example.com/","comment":""}],"tcp":[]},"oracle":{"service":"ORCL","user":"otel","capacity":true,"capacity_pdbs":[]},"tomcat":{"logs":[],"time_zone":"","login_path":""}}`
	if string(b) != want {
		t.Errorf("settings_values:\n got %s\nwant %s", b, want)
	}
}

// the file keeps the values, an empty list stays a managed (empty) group, a missing group stays unmanaged
func TestSettingsOverlayValuesRoundTrip(t *testing.T) {
	ov := SettingsOverlay{Revision: 4, Set: SettingsSet{"rescan": true}, Values: valuesJSON(t, `{"checks":{"http":[],"tcp":[{"endpoint":"db.example.com:1521","comment":"db"}]},"tomcat":{"logs":[],"time_zone":"UTC","login_path":"^/login"}}`)}
	b, err := MarshalSettingsOverlay(ov)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "config", "settings.cp.yaml")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSettingsOverlay(p)
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	if got.Revision != 4 || strings.Join(got.Values.Groups(), ",") != "checks,tomcat" || got.Values.Checks.HTTP == nil || len(got.Values.Checks.TCP) != 1 ||
		got.Values.Tomcat.LoginPath != "^/login" || got.String() != "rescan on; values of checks, tomcat" {
		t.Errorf("round trip: %+v\n%s", got, b)
	}
	// the effective answers below the prefix see the file
	ans := "agent:\n  url: https://agent.example.com/agent/\n  control_plane_key: \"" + testKey + "\"\n  settings:\n    allow: [checks, tomcat]\n"
	if err := os.WriteFile(filepath.Join(dir, "answers.yaml"), []byte(ans), 0o644); err != nil {
		t.Fatal(err)
	}
	eff, err := LoadEffectiveAnswers(dir)
	if err != nil || len(eff.Checks.TCP) != 1 || eff.Services["tomcat"].TimeZone != "UTC" {
		t.Errorf("effective from the file: %v %+v %+v", err, eff.Checks, eff.Services)
	}
	if (SettingsOverlay{}).Empty() != true || (SettingsOverlay{Values: &SettingsValues{}}).Empty() != true || ov.Empty() {
		t.Error("Empty")
	}
}
