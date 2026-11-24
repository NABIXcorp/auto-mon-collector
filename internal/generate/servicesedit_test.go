package generate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/assets"
	"github.com/NABIXcorp/auto-mon-collector/internal/detect"
)

var editOnly = AgentServicesEdit{Allow: true}

func TestCheckServicesSet(t *testing.T) {
	off := false
	ans := map[string]Service{"redis": {Enabled: &off, Locked: true}, "nginx": {Enabled: &off}}
	ok := ServicesSet{"nginx": {On: true, Port: 80, StatusPath: "/nginx_status"}}
	if err := CheckServicesSet(ok, editOnly, ans); err != nil {
		t.Errorf("a good set: %v", err)
	}
	cases := []struct {
		name string
		set  ServicesSet
		edit AgentServicesEdit
		want string
	}{
		{"switch off", ok, AgentServicesEdit{}, "agent.services_edit.allow"},
		{"unknown kind", ServicesSet{"docker": {On: true, Port: 2375}}, editOnly, `kind "docker"`},
		{"oracle is not switchable", ServicesSet{"oracle": {On: true, Port: 1521}}, editOnly, `kind "oracle"`},
		{"port 0", ServicesSet{"nginx": {On: true}}, editOnly, "port 0"},
		{"port too big", ServicesSet{"nginx": {On: true, Port: 70000}}, editOnly, "port 70000"},
		{"bad path", ServicesSet{"nginx": {On: true, Port: 80, StatusPath: "/x?y=1"}}, editOnly, "status_path"},
		{"no slash", ServicesSet{"nginx": {On: true, Port: 80, StatusPath: "nginx_status"}}, editOnly, "status_path"},
		{"path for redis", ServicesSet{"redis": {On: true, Port: 6379, StatusPath: "/x"}}, editOnly, "nginx setting"},
		{"locked", ServicesSet{"redis": {On: true, Port: 6380}}, editOnly, "locked"},
	}
	for _, c := range cases {
		if err := CheckServicesSet(c.set, c.edit, ans); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", c.name, err, c.want)
		}
	}
	// a locked kind switched OFF (withdrawn) is fine: it changes nothing
	if err := CheckServicesSet(ServicesSet{"redis": {On: false}}, editOnly, ans); err != nil {
		t.Errorf("off for a locked kind: %v", err)
	}
	if err := CheckServicesSet(ServicesSet{}, editOnly, ans); err != nil {
		t.Errorf("empty set: %v", err)
	}
}

// the merge rule: answers win; enabled: false WITHOUT locked is "not decided" and may be switched on
func TestEffectiveServices(t *testing.T) {
	on, off := true, false
	set := ServicesSet{"redis": {On: true, Port: 6380}, "nginx": {On: true, Port: 8080, StatusPath: "/st"}}
	cases := []struct {
		name   string
		ans    map[string]Service
		kind   string
		wantOn bool
		port   int
	}{
		{"absent", nil, "redis", true, 6380},
		{"enabled false (not decided)", map[string]Service{"redis": {Enabled: &off}}, "redis", true, 6380},
		{"enabled false + locked", map[string]Service{"redis": {Enabled: &off, Locked: true}}, "redis", false, 0},
		{"enabled true: the answers' port", map[string]Service{"redis": {Enabled: &on, Port: 6390}}, "redis", true, 6390},
		{"nginx with its path", nil, "nginx", true, 8080},
	}
	for _, c := range cases {
		got := EffectiveServices(c.ans, set)[c.kind]
		isOn := got.Enabled != nil && *got.Enabled
		if isOn != c.wantOn || got.Port != c.port {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
	if got := EffectiveServices(nil, set)["nginx"]; got.StatusPath != "/st" {
		t.Errorf("nginx path: %+v", got)
	}
	ans := map[string]Service{"redis": {Enabled: &off}}
	EffectiveServices(ans, set)
	if *ans["redis"].Enabled || len(ans) != 1 {
		t.Error("the answers map was changed")
	}
	// withdrawn = the answers decide
	if got := EffectiveServices(ans, ServicesSet{"redis": {On: false}})["redis"]; *got.Enabled {
		t.Errorf("off: %+v", got)
	}
}

func agentAnswers(edit bool) *Agent {
	return &Agent{URL: "https://agent.example.com/agent/", ControlPlaneKey: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ServicesEdit: AgentServicesEdit{Allow: edit}}
}

func TestGenerateWithServiceSwitches(t *testing.T) {
	off := false
	redis := detect.Finding{ID: "redis", Confidence: "high", Profile: true, Ports: []int{6380}}
	nginx := detect.Finding{ID: "nginx", Confidence: "high", Ports: []int{80, 443}, Notes: []string{"no monitoring-agent profile yet: not monitored"}}
	h := Host{Findings: []detect.Finding{nginx, redis}}
	a := Answers{Services: map[string]Service{"redis": {Enabled: &off}}, Agent: agentAnswers(true)}

	// without a set: Redis off (on 6380: no switch needed), nginx not monitored
	out, err := Generate(h, a)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out.HostEnv), "REDIS_") || strings.Contains(string(out.HostEnv), "NGINX_") || len(out.Enabled) != 0 {
		t.Fatalf("no set: %v\n%s", out.Enabled, out.HostEnv)
	}

	h.ServicesCP = ServicesSet{"redis": {On: true, Port: 6380}, "nginx": {On: true, Port: 80, StatusPath: "/nginx_status"}}
	out, err = Generate(h, a)
	if err != nil {
		t.Fatal(err)
	}
	env := string(out.HostEnv)
	for _, want := range []string{"REDIS_PORT=6380\n", "NGINX_MON=on\n", "NGINX_PORT=80\n", "NGINX_STATUS_PATH=/nginx_status\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("host.env lacks %q:\n%s", want, env)
		}
	}
	if strings.Join(out.Enabled, ",") != "nginx,redis" {
		t.Errorf("enabled: %v", out.Enabled)
	}
	var inv InventoryDoc
	if err := json.Unmarshal(out.Inventory, &inv); err != nil {
		t.Fatal(err)
	}
	for _, s := range inv.Services {
		if !s.Monitored {
			t.Errorf("inventory: %s not monitored", s.ID)
		}
	}
	if !strings.Contains(string(out.HostYAML), "ports: [80, 443, 6380]") {
		t.Errorf("netconn:\n%s", out.HostYAML)
	}

	// the host owner's switch off: an installed set is ignored
	a.Agent = agentAnswers(false)
	if out, _ := Generate(h, a); strings.Contains(string(out.HostEnv), "REDIS_PORT") || strings.Contains(string(out.HostEnv), "NGINX_") {
		t.Errorf("switch off, set used:\n%s", out.HostEnv)
	}
	// locked in the answers: the set is ignored for that kind
	a.Agent = agentAnswers(true)
	a.Services = map[string]Service{"redis": {Enabled: &off, Locked: true}}
	if out, _ := Generate(h, a); strings.Contains(string(out.HostEnv), "REDIS_PORT") || !strings.Contains(string(out.HostEnv), "NGINX_MON=on") {
		t.Errorf("locked:\n%s", out.HostEnv)
	}
	// nginx switched on but not found by the scan: nothing
	h.Findings = []detect.Finding{redis}
	if out, _ := Generate(h, a); strings.Contains(string(out.HostEnv), "NGINX_") {
		t.Errorf("nginx not found but on:\n%s", out.HostEnv)
	}
}

// nginx from the answers alone (no agent): enabled: true, own port / path; default stays off
func TestNginxFromAnswers(t *testing.T) {
	on := true
	nginx := detect.Finding{ID: "nginx", Confidence: "high", Ports: []int{8081}}
	out, _ := Generate(Host{Findings: []detect.Finding{nginx}}, Answers{})
	if strings.Contains(string(out.HostEnv), "NGINX_") {
		t.Errorf("nginx on by default:\n%s", out.HostEnv)
	}
	out, _ = Generate(Host{Findings: []detect.Finding{nginx}}, Answers{Services: map[string]Service{"nginx": {Enabled: &on, Port: 8081}}})
	if !strings.Contains(string(out.HostEnv), "NGINX_MON=on\nNGINX_PORT=8081\nNGINX_STATUS_PATH=/nginx_status\n") {
		t.Errorf("host.env:\n%s", out.HostEnv)
	}
	// the base config has the matching receiver_creator rule
	cfg := string(assets.BaseConfig())
	for _, want := range []string{`"${env:NGINX_MON:-off}" == "on"`, "endpoint: http://127.0.0.1:${env:NGINX_PORT:-80}${env:NGINX_STATUS_PATH:-/nginx_status}"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config.yaml lacks %q", want)
		}
	}
}

func TestAnswersServicesKeys(t *testing.T) {
	load := func(s string) (Answers, error) {
		p := filepath.Join(t.TempDir(), "answers.yaml")
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		return LoadAnswers(p)
	}
	a, err := load("services:\n  nginx:\n    enabled: true\n    port: 8080\n    status_path: /basic_status\n  redis:\n    enabled: false\n    locked: true\n    port: 6380\n" +
		"agent:\n  url: https://agent.example.com/agent/\n  control_plane_key: \"ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\n  services_edit:\n    allow: true\n")
	if err != nil || !a.Agent.ServicesEdit.Allow || !a.Services["redis"].Locked || a.Services["nginx"].StatusPath != "/basic_status" {
		t.Fatalf("%v %+v", err, a)
	}
	b, _ := a.Marshal()
	if !strings.Contains(string(b), "services_edit:") || !strings.Contains(string(b), "locked: true") {
		t.Errorf("marshal:\n%s", b)
	}
	for _, s := range []string{
		"services:\n  oracle:\n    port: 1521\n",
		"services:\n  redis:\n    port: 70000\n",
		"services:\n  redis:\n    status_path: /x\n",
		"services:\n  nginx:\n    status_path: x\n",
		"services:\n  docker:\n    enabled: true\n",
	} {
		if _, err := load(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestServicesOverlayFileRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "services.cp.yaml")
	ov := ServicesOverlay{Revision: 7, Set: ServicesSet{"nginx": {On: true, Port: 80}, "redis": {On: false}}.Normalized()}
	b, err := MarshalServicesOverlay(ov)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "(revision 7)") {
		t.Errorf("header:\n%s", b)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadServicesOverlay(p)
	if err != nil || got.Revision != 7 || got.Set.String() != "nginx on :80 /nginx_status, redis off" {
		t.Fatalf("%v %+v %s", err, got, got.Set)
	}
	for _, bad := range []string{"revision: 1\nset:\n  docker: {on: true, port: 1}\n", "revision: 1\nset: {}\nextra: 1\n"} {
		if err := os.WriteFile(p, []byte(bad), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadServicesOverlay(p); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if ov, err := LoadServicesOverlay(filepath.Join(t.TempDir(), "none")); err != nil || ov.Revision != 0 {
		t.Errorf("missing: %v %+v", err, ov)
	}
	// LocalServices: only with the switch on
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(ServicesFile)), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if ov, _ := LocalServices(agentAnswers(false), dir); ov.Revision != 0 {
		t.Errorf("switch off: %+v", ov)
	}
	if ov, _ := LocalServices(agentAnswers(true), dir); ov.Revision != 7 {
		t.Errorf("switch on: %+v", ov)
	}
}
