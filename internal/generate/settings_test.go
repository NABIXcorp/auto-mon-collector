package generate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func settingsAnswers(t *testing.T, extra string) Answers {
	t.Helper()
	p := filepath.Join(t.TempDir(), "answers.yaml")
	body := "agent:\n  url: https://agent.example.com/agent/\n  control_plane_key: \"" + testKey + "\"\n" + extra
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := LoadAnswers(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// pinned = the answers write agent.<key>.allow (any value); other keys of the same section do not pin it
func TestSettingsPinned(t *testing.T) {
	a := settingsAnswers(t, "  disk_scan:\n    allow: false\n  rescan:\n    allow: true\n  docker: {}\n"+
		"  allow_edit:\n    max_probes: 40\n  settings:\n    allow: [disk_scan, docker, allow_edit]\n")
	if got := strings.Join(a.Agent.Pinned(), ","); got != "disk_scan,rescan" {
		t.Errorf("pinned: %q", got)
	}
	// answers built in code: a switch that is on counts as written
	code := Agent{Rescan: AgentRescan{Allow: true}}
	if got := strings.Join(code.Pinned(), ","); got != "rescan" {
		t.Errorf("pinned (code): %q", got)
	}
}

func TestSettingsAllowValidated(t *testing.T) {
	for _, bad := range []string{"[update]", "[disk_scan, disk_scan]", "[site]"} {
		p := filepath.Join(t.TempDir(), "answers.yaml")
		body := "agent:\n  url: https://agent.example.com/agent/\n  control_plane_key: \"" + testKey + "\"\n  settings:\n    allow: " + bad + "\n"
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadAnswers(p); err == nil || !strings.Contains(err.Error(), "agent.settings.allow") {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if got, err := ParseSettingsAllow(" rescan , disk_scan"); err != nil || strings.Join(got, ",") != "disk_scan,rescan" {
		t.Errorf("parse: %q %v", got, err)
	}
	for _, none := range []string{"", "none"} {
		if got, err := ParseSettingsAllow(none); err != nil || got != nil {
			t.Errorf("parse %q: %q %v", none, got, err)
		}
	}
	if _, err := ParseSettingsAllow("disk_scan,update"); err == nil || !strings.Contains(err.Error(), `unknown key "update"`) {
		t.Errorf("parse unknown: %v", err)
	}
}

func TestCheckSettingsSet(t *testing.T) {
	a := settingsAnswers(t, "  disk_scan:\n    allow: false\n  settings:\n    allow: [disk_scan, rescan, docker]\n")
	cases := []struct {
		set  SettingsSet
		want string // "" = accepted
	}{
		{SettingsSet{"rescan": true, "docker": false}, ""},
		{SettingsSet{}, ""},
		{SettingsSet{"rescan": true, "update": true}, `unknown key "update"`},
		{SettingsSet{"services_edit": true}, "services_edit is not in answers.yaml agent.settings.allow"},
		{SettingsSet{"rescan": true, "disk_scan": true}, "disk_scan is pinned"},
	}
	for _, c := range cases {
		err := CheckSettingsSet(c.set, a.Agent)
		if (c.want == "" && err != nil) || (c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want))) {
			t.Errorf("%v: %v (want %q)", c.set, err, c.want)
		}
	}
	off := settingsAnswers(t, "")
	if err := CheckSettingsSet(SettingsSet{}, off.Agent); err == nil || !strings.Contains(err.Error(), "agent.settings.allow") {
		t.Errorf("no consent: %v", err)
	}
}

// the one rule: pinned = answers; else allowed + in the set = the set; else the default (off)
func TestEffectiveAgent(t *testing.T) {
	a := settingsAnswers(t, "  disk_scan:\n    allow: false\n  rescan:\n    allow: true\n  settings:\n    allow: [disk_scan, rescan, docker, services_edit]\n")
	set := SettingsSet{"disk_scan": true, "rescan": false, "docker": true, "allow_edit": true}
	eff := EffectiveAgent(*a.Agent, set)
	if eff.DiskScan.Allow || !eff.Rescan.Allow { // pinned
		t.Errorf("pinned keys changed: disk_scan %v rescan %v", eff.DiskScan.Allow, eff.Rescan.Allow)
	}
	if !eff.Docker.Allow { // allowed + set
		t.Error("docker not switched on")
	}
	if eff.AllowEdit.Allow { // set, but not in the consent list
		t.Error("allow_edit switched without consent")
	}
	if eff.ServicesEdit.Allow { // allowed, not in the set
		t.Error("services_edit switched without being in the set")
	}
	if a.Agent.Docker.Allow {
		t.Error("the caller's agent was changed")
	}
	// the effective copy still knows the pins: a set switching docker off again is accepted, disk_scan still refused
	if err := CheckSettingsSet(SettingsSet{"docker": false}, &eff); err != nil {
		t.Errorf("effective copy: %v", err)
	}
	if err := CheckSettingsSet(SettingsSet{"disk_scan": true}, &eff); err == nil {
		t.Error("effective copy forgot the pin")
	}
	if got := strings.Join(eff.Pinned(), ","); got != "disk_scan,rescan" {
		t.Errorf("effective pinned: %q", got)
	}
}

func TestEffectiveAnswersFromTheInstalledFile(t *testing.T) {
	prefix := t.TempDir()
	if err := os.MkdirAll(filepath.Join(prefix, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "agent:\n  url: https://agent.example.com/agent/\n  control_plane_key: \"" + testKey + "\"\n  settings:\n    allow: [rescan]\n"
	if err := os.WriteFile(filepath.Join(prefix, "answers.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ov, err := MarshalSettingsOverlay(SettingsOverlay{Revision: 3, Set: SettingsSet{"rescan": true}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prefix, filepath.FromSlash(SettingsFile)), ov, 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := LoadEffectiveAnswers(prefix)
	if err != nil || !a.Agent.Rescan.Allow {
		t.Fatalf("effective: %v %+v", err, a.Agent)
	}
	raw, _ := LoadAnswers(filepath.Join(prefix, "answers.yaml"))
	_, sov, err := EffectiveAnswers(raw, prefix)
	if err != nil || sov.Revision != 3 || sov.Set.String() != "rescan on" {
		t.Errorf("overlay: %v %+v", err, sov)
	}
	// saved answers stay the owner's: no rescan written
	b, _ := raw.Marshal()
	if strings.Contains(string(b), "rescan:") {
		t.Errorf("the set leaked into the answers: %s", b)
	}
	// no consent: the installed file is ignored
	if err := os.WriteFile(filepath.Join(prefix, "answers.yaml"), []byte(strings.Replace(body, "  settings:\n    allow: [rescan]\n", "", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if a, err := LoadEffectiveAnswers(prefix); err != nil || a.Agent.Rescan.Allow {
		t.Errorf("without consent: %v %+v", err, a.Agent)
	}
	// a damaged file is an error, not "off"
	if err := os.WriteFile(filepath.Join(prefix, filepath.FromSlash(SettingsFile)), []byte("revision: 1\nset: {update: true}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSettingsOverlay(filepath.Join(prefix, filepath.FromSlash(SettingsFile))); err == nil || !strings.Contains(err.Error(), `unknown key "update"`) {
		t.Errorf("unknown key in the file: %v", err)
	}
}

// a pin to OFF survives the rewrite of answers.yaml by apply (omitempty would drop "allow: false")
func TestMarshalKeepsAPinToOff(t *testing.T) {
	a := settingsAnswers(t, "  disk_scan:\n    allow: false\n    exclude: [/home]\n  docker:\n    allow: false\n  settings:\n    allow: [docker, rescan]\n")
	b, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "answers.yaml")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	again, err := LoadAnswers(p)
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	if got := strings.Join(again.Agent.Pinned(), ","); got != "disk_scan,docker" {
		t.Errorf("pins after a rewrite: %q\n%s", got, b)
	}
	if strings.Join(again.Agent.DiskScan.Exclude, ",") != "/home" || strings.Join(again.Agent.Settings.Allow, ",") != "docker,rescan" {
		t.Errorf("other fields: %+v", again.Agent)
	}
	b2, _ := again.Marshal()
	if string(b2) != string(b) {
		t.Errorf("not stable:\n%s\n---\n%s", b, b2)
	}
	// nothing pinned: no extra keys
	plain := settingsAnswers(t, "")
	pb, _ := plain.Marshal()
	if strings.Contains(string(pb), "allow: false") {
		t.Errorf("unpinned answers got allow: false:\n%s", pb)
	}
}
