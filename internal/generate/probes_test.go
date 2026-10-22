package generate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func demoProbes() Probes {
	return Probes{
		TCP:  []TCPProbe{{Name: "db_primary", Host: "db.example.com", Port: 1521}, {Name: "app2", Host: "192.0.2.10", Port: 8080, Path: "private"}},
		HTTP: []HTTPProbe{{Name: "payments_api", URL: "https://api.example.com/health?x=1"}, {Name: "local_app", URL: "http://127.0.0.1:8080/"}},
		Ping: []PingProbe{{Name: "gw", Host: "192.0.2.1", Path: "public"}, {Name: "gw_name", Host: "gw.example.com"}},
	}
}

func TestProbesGenerateCloudproberAndScrape(t *testing.T) {
	var a Answers
	a.Probes = demoProbes()
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	out, err := Generate(Host{}, a)
	if err != nil {
		t.Fatal(err)
	}
	if out.Probes == nil || !out.Probes.Ping {
		t.Fatalf("probes: %+v", out.Probes)
	}
	cfg := string(out.Probes.Config)
	for _, want := range []string{
		`host: "127.0.0.1"`, "port: 9313",
		`file_path: "@PREFIX@/config/cloudprober/cloudprober-tcp.json"`, "ping_probe { use_datagram_socket: false }",
		`name: "http_payments_api"`, "protocol: HTTPS", "port: 443", `relative_url: "/health?x=1"`,
		`name: "http_local_app"`, "protocol: HTTP", "port: 8080", `ip: "127.0.0.1"`,
		"interval_msec: 30000", `metrics_prefix: "cloudprober_"`, `value: "@target.label.target@"`,
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("cloudprober.cfg lacks %q:\n%s", want, cfg)
		}
	}
	tcp := string(out.Probes.Targets["cloudprober-tcp.json"])
	if !strings.Contains(tcp, `"name": "db.example.com"`) || strings.Contains(tcp, `"ip": "db.example.com"`) ||
		!strings.Contains(tcp, `"ip": "192.0.2.10"`) || !strings.Contains(tcp, `"target": "app2"`) {
		t.Errorf("tcp targets:\n%s", tcp)
	}
	y := string(out.HostYAML)
	var doc map[string]any
	if err := yaml.Unmarshal(out.HostYAML, &doc); err != nil {
		t.Fatalf("host.yaml: %v\n%s", err, y)
	}
	recv := doc["service"].(map[string]any)["pipelines"].(map[string]any)["metrics"].(map[string]any)["receivers"].([]any)
	if recv[len(recv)-1] != "prometheus/cloudprober" || !strings.Contains(y, `targets: ["127.0.0.1:9313"]`) {
		t.Errorf("scrape job missing: %v\n%s", recv, y)
	}
	if os.Getenv("AMC_WRITE_PROBES") != "" { // manual check: cloudprober --configtest on the generated file
		d := os.Getenv("AMC_WRITE_PROBES")
		c := strings.ReplaceAll(cfg, ProbePrefix, d)
		os.MkdirAll(filepath.Join(d, "config"), 0o755)
		os.WriteFile(filepath.Join(d, "cloudprober.cfg"), []byte(c), 0o644)
		for n, b := range out.Probes.Targets {
			os.WriteFile(filepath.Join(d, "config", n), b, 0o644)
		}
	}
}

func TestNoProbesNoCloudprober(t *testing.T) {
	out, err := Generate(Host{}, Answers{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Probes != nil || strings.Contains(string(out.HostYAML), "cloudprober") {
		t.Errorf("probes without answers: %+v", out.Probes)
	}
	var a Answers
	a.Probes.HTTP = []HTTPProbe{{Name: "x", URL: "https://example.com/"}}
	out, _ = Generate(Host{}, a)
	if out.Probes == nil || out.Probes.Ping {
		t.Errorf("http only: ping capability must be off: %+v", out.Probes)
	}
}

func TestProbeValidation(t *testing.T) {
	bad := []Probes{
		{IntervalS: 5, Ping: []PingProbe{{Name: "a", Host: "h"}}},
		{TCP: []TCPProbe{{Name: "A", Host: "h", Port: 1}}},
		{TCP: []TCPProbe{{Name: "a", Host: "h x", Port: 1}}},
		{TCP: []TCPProbe{{Name: "a", Host: "h", Port: 0}}},
		{TCP: []TCPProbe{{Name: "a", Host: "h", Port: 1}, {Name: "b", Host: "h", Port: 1}}},
		{TCP: []TCPProbe{{Name: "a", Host: "h", Port: 1}}, Ping: []PingProbe{{Name: "a", Host: "h"}}},
		{HTTP: []HTTPProbe{{Name: "a", URL: "ftp://example.com/"}}},
		{HTTP: []HTTPProbe{{Name: "a", URL: "https://u:p@example.com/"}}},
		{HTTP: []HTTPProbe{{Name: "a", URL: `https://example.com/"x`}}},
		{Ping: []PingProbe{{Name: "a", Host: "h;rm"}}},
	}
	for i, p := range bad {
		var a Answers
		a.Probes = p
		if a.Validate() == nil {
			t.Errorf("case %d accepted: %+v", i, p)
		}
	}
	var a Answers
	a.Probes = demoProbes()
	a.Probes.TCP = append(a.Probes.TCP, TCPProbe{Name: "v6", Host: "2001:db8::7", Port: 443})
	if err := a.Validate(); err != nil {
		t.Errorf("valid probes refused: %v", err)
	}
}

func TestProbesRoundTripInAnswersFile(t *testing.T) {
	var a Answers
	a.Probes = demoProbes()
	b, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "answers.yaml")
	os.WriteFile(p, b, 0o644)
	got, err := LoadAnswers(p)
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	if len(got.Probes.TCP) != 2 || got.Probes.HTTP[0].URL != a.Probes.HTTP[0].URL || got.Probes.Ping[0].Host != "192.0.2.1" {
		t.Errorf("round trip: %+v", got.Probes)
	}
	if b2, _ := (Answers{}).Marshal(); strings.Contains(string(b2), "probes") {
		t.Errorf("empty answers write probes:\n%s", b2)
	}
}

// v0.14.0: `path` (which address of the peer: a mesh strand) reaches the metrics as a label; ping = one probe per
// target with fixed labels (an unresolvable DNS name lost the file target's labels: target="").
func TestProbePathLabelAndPingPerTarget(t *testing.T) {
	p := Probes{
		TCP:  []TCPProbe{{Name: "mesh_db_private_1521", Host: "198.51.100.31", Port: 1521, Path: "private"}, {Name: "plain", Host: "db.example.com", Port: 22}},
		HTTP: []HTTPProbe{{Name: "api_public", URL: "https://api.example.com/", Path: "public"}},
		Ping: []PingProbe{{Name: "gw", Host: "gw.example.com"}, {Name: "db_private", Host: "198.51.100.31", Path: "private"}},
	}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	pf := probeFiles(p)
	cfg := string(pf.Config)
	for _, want := range []string{
		`additional_label { key: "path" value: "@target.label.path@" }`, // tcp: from the file target
		`name: "ping_gw"`, `targets { host_names: "gw.example.com" }`, `additional_label { key: "target" value: "gw" }`,
		`name: "ping_db_private"`, `additional_label { key: "path" value: "private" }`,
		`additional_label { key: "path" value: "public" }`, // http: fixed
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("cloudprober.cfg lacks %q:\n%s", want, cfg)
		}
	}
	if _, ok := pf.Targets["cloudprober-ping.json"]; ok || strings.Contains(cfg, "cloudprober-ping.json") {
		t.Error("ping must not use file targets any more")
	}
	if tcp := string(pf.Targets["cloudprober-tcp.json"]); !strings.Contains(tcp, `"path": "private"`) || strings.Count(tcp, `"path"`) != 1 {
		t.Errorf("tcp targets:\n%s", tcp)
	}
	// no path anywhere = no path label at all (hosts without mesh paths keep exactly their metrics)
	plain := string(probeFiles(Probes{TCP: []TCPProbe{{Name: "a", Host: "db.example.com", Port: 22}}}).Config)
	if strings.Contains(plain, `"path"`) {
		t.Errorf("no path, but a path label:\n%s", plain)
	}
	for _, bad := range []Probes{
		{TCP: []TCPProbe{{Name: "a", Host: "db.example.com", Port: 22, Path: "lan"}}},
		{Ping: []PingProbe{{Name: "a", Host: "db.example.com", Path: "PRIVATE"}}},
		{HTTP: []HTTPProbe{{Name: "a", URL: "https://api.example.com/", Path: " public"}}},
	} {
		if err := bad.validate(); err == nil || !strings.Contains(err.Error(), "path") {
			t.Errorf("want a path error for %+v, got %v", bad, err)
		}
	}
}
