package generate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testKey = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestAgentAnswersValidation(t *testing.T) {
	good := Agent{URL: "https://agent.example.com/agent/", ControlPlaneKey: testKey,
		Allow: Allow{Domains: []string{"*.example.com"}, Networks: []string{"192.0.2.0/24"}, Ports: []int{443}}}
	if err := (&good).validate(); err != nil {
		t.Fatal(err)
	}
	loop := good
	loop.URL = "http://127.0.0.1:18091/agent/"
	if err := (&loop).validate(); err != nil {
		t.Errorf("http to the loopback refused: %v", err)
	}
	bad := map[string]func(a *Agent){
		"http":         func(a *Agent) { a.URL = "http://agent.example.com/agent/" },
		"credentials":  func(a *Agent) { a.URL = "https://u:p@agent.example.com/" },
		"no key":       func(a *Agent) { a.ControlPlaneKey = "" },
		"short key":    func(a *Agent) { a.ControlPlaneKey = "ed25519:AAAA" },
		"domain upper": func(a *Agent) { a.Allow.Domains = []string{"Example.COM"} },
		"domain mid *": func(a *Agent) { a.Allow.Domains = []string{"a.*.example.com"} },
		"cidr":         func(a *Agent) { a.Allow.Networks = []string{"192.0.2.1"} },
		"port":         func(a *Agent) { a.Allow.Ports = []int{0} },
		"interval":     func(a *Agent) { a.Allow.MinIntervalS = 5 },
		"max probes":   func(a *Agent) { a.Allow.MaxProbes = 500 },
	}
	for name, f := range bad {
		a := good
		a.Allow.Domains = append([]string{}, good.Allow.Domains...)
		f(&a)
		if err := (&a).validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAllowMergeAndTemplate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "allow.yaml")
	if err := os.WriteFile(p, []byte("domains: [\"*.example.com\"]\nports: [443]\nmax_probes: 10\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tmpl, err := LoadAllow(p)
	if err != nil {
		t.Fatal(err)
	}
	m := tmpl.Merge(Allow{Domains: []string{"api.example.org", "*.example.com"}, Ports: []int{5432}, Ping: true})
	if strings.Join(m.Domains, ",") != "*.example.com,api.example.org" || len(m.Ports) != 2 || m.MaxProbes != 10 ||
		m.MinIntervalS != 15 || !m.Ping {
		t.Fatalf("merge: %+v", m)
	}
	if err := os.WriteFile(p, []byte("domain: [x]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAllow(p); err == nil {
		t.Error("unknown key in a template accepted")
	}
}

func TestGenerateWithAgent(t *testing.T) {
	a := Answers{Agent: &Agent{URL: "https://agent.example.com/agent/", ControlPlaneKey: testKey}}
	h := Host{AgentAllow: Allow{}.Merge(Allow{Domains: []string{"*.example.com"}, Ports: []int{443}})}
	out, err := Generate(h, a)
	if err != nil {
		t.Fatal(err)
	}
	if out.Probes == nil || !strings.Contains(string(out.Probes.Config), "No probes yet") ||
		!strings.Contains(string(out.HostYAML), "prometheus/cloudprober") {
		t.Fatalf("agent without probes: Cloudprober must still run:\n%s", out.HostYAML)
	}
	// the agent's last list is part of the files; the scrape interval stays the answers' (default 30 s)
	h.AgentProbes = Probes{IntervalS: 15, TCP: []TCPProbe{{Name: "link_a_b", Host: "db.example.com", Port: 443}}}
	out, _ = Generate(h, a)
	if !strings.Contains(string(out.Probes.Targets["targets-tcp.json"]), "link_a_b") ||
		!strings.Contains(string(out.Probes.Config), "interval_msec: 15000") || !strings.Contains(string(out.HostYAML), "scrape_interval: 30s") {
		t.Fatalf("agent list not generated:\n%s\n%s", out.Probes.Config, out.HostYAML)
	}
	// the allowlist got smaller: the applied list is left out (and said so), not installed
	h.AgentAllow = Allow{}.Merge(Allow{Domains: []string{"other.example.org"}, Ports: []int{443}})
	out, _ = Generate(h, a)
	if _, ok := out.Probes.Targets["targets-tcp.json"]; ok || !strings.Contains(strings.Join(out.Defaults, " "), "outside the allowlist") {
		t.Fatalf("list outside the allowlist was installed: %v", out.Defaults)
	}
}

// v0.32.0: agent.rescan {allow} is read strictly (only allow, a mapping, a bool); missing = off; it survives the
// answers.yaml round trip.
func TestAgentRescanAnswers(t *testing.T) {
	base := "agent:\n  url: https://agent.example.com/agent/\n  control_plane_key: \"" + testKey + "\"\n"
	load := func(extra string) (Answers, error) {
		p := filepath.Join(t.TempDir(), "answers.yaml")
		if err := os.WriteFile(p, []byte(base+extra), 0o644); err != nil {
			t.Fatal(err)
		}
		return LoadAnswers(p)
	}
	a, err := load("")
	if err != nil || a.Agent.Rescan.Allow {
		t.Fatalf("default: %v %+v", err, a.Agent.Rescan)
	}
	a, err = load("  rescan:\n    allow: true\n")
	if err != nil || !a.Agent.Rescan.Allow {
		t.Fatalf("allow: %v %+v", err, a.Agent.Rescan)
	}
	b, err := a.Marshal()
	if err != nil || !strings.Contains(string(b), "rescan:\n        allow: true") && !strings.Contains(string(b), "rescan:\n    allow: true") {
		t.Errorf("round trip lost rescan: %v\n%s", err, b)
	}
	for name, extra := range map[string]string{
		"unknown key": "  rescan:\n    allow: true\n    every: 5m\n",
		"scalar":      "  rescan: true\n",
		"not a bool":  "  rescan:\n    allow: sometimes\n",
	} {
		if _, err := load(extra); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
