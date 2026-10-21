package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

func TestCanonicalJSONVectors(t *testing.T) {
	b, err := os.ReadFile("../../testdata/agent/canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct {
		Name, In, Out string
		Drop          []string
	}
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		got, err := CanonicalJSON([]byte(v.In), v.Drop...)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if string(got) != v.Out {
			t.Errorf("%s:\n got %s\nwant %s", v.Name, got, v.Out)
		}
	}
	if _, err := CanonicalJSON([]byte(`{"a":1} {"b":2}`)); err == nil {
		t.Error("trailing data accepted")
	}
}

func TestSignString(t *testing.T) {
	got := string(SignString("GET", "/agent/v1/desired?have=3", "1792500000", "nonce-0123456789ab", nil))
	want := "GET\n/agent/v1/desired?have=3\n1792500000\nnonce-0123456789ab\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Fatalf("got %q", got)
	}
	if n := Nonce(); len(n) < 16 || len(n) > 64 || strings.ContainsAny(n, "+/=") {
		t.Fatalf("nonce %q", n)
	}
}

var testAllow = generate.Allow{}.Merge(generate.Allow{Domains: []string{"*.example.com", "api.example.org"},
	Networks: []string{"192.0.2.0/24"}, Ports: []int{443, 5432}, MaxProbes: 5, MinIntervalS: 15})

func sign(t *testing.T, key ed25519.PrivateKey, doc map[string]any) []byte {
	t.Helper()
	b, _ := json.Marshal(doc)
	c, err := CanonicalJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	doc["sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(key, c))
	raw, _ := json.Marshal(doc)
	return raw
}

func TestVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1792500000, 0)
	good := func() map[string]any {
		return map[string]any{"host": "app-1", "revision": 4, "issued_at": now.Unix(), "expires_at": now.Unix() + 600,
			"probes": map[string]any{"interval_s": 30, "tcp": []any{map[string]any{"name": "db", "host": "db.example.com", "port": 5432}},
				"http": []any{map[string]any{"name": "api", "url": "https://api.example.org/health"}}, "ping": []any{}}}
	}
	if d, err := Verify(sign(t, priv, good()), pub, "app-1", 3, now, testAllow); err != nil || d.Revision != 4 || len(d.Probes.TCP) != 1 {
		t.Fatalf("good document: %v %+v", err, d)
	}
	raw := sign(t, priv, good())
	tampered := []byte(strings.Replace(string(raw), `"port":5432`, `"port":443`, 1))
	cases := map[string]struct {
		raw     []byte
		applied int64
		want    string
	}{
		"other key":  {sign(t, other, good()), 3, "bad signature"},
		"tampered":   {tampered, 3, "bad signature"},
		"old rev":    {raw, 4, "not newer"},
		"other host": {func() []byte { d := good(); d["host"] = "app-2"; return sign(t, priv, d) }(), 3, "for host"},
		"expired":    {func() []byte { d := good(); d["expires_at"] = now.Unix(); return sign(t, priv, d) }(), 3, "expired"},
		"no sig":     {[]byte(`{"host":"app-1","revision":5}`), 3, "signature"},
		"bad name": {func() []byte {
			d := good()
			d["probes"] = map[string]any{"tcp": []any{map[string]any{"name": "Bad Name", "host": "db.example.com", "port": 5432}}}
			return sign(t, priv, d)
		}(), 3, "name"},
		"outside allowlist": {func() []byte {
			d := good()
			d["probes"] = map[string]any{"tcp": []any{map[string]any{"name": "x", "host": "evil.example.net", "port": 5432}}}
			return sign(t, priv, d)
		}(), 3, "allowlist"},
		"unknown field": {func() []byte { d := good(); d["command"] = "rm -rf /"; return sign(t, priv, d) }(), 3, "not a probe document"},
	}
	for name, c := range cases {
		_, err := Verify(c.raw, pub, "app-1", c.applied, now, testAllow)
		var rej *Reject
		if !errors.As(err, &rej) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want a rejection containing %q", name, err, c.want)
		}
	}
}

func TestCheckAllow(t *testing.T) {
	p := func(tcp []generate.TCPProbe, http []generate.HTTPProbe, ping []generate.PingProbe, iv int) generate.Probes {
		return generate.Probes{IntervalS: iv, TCP: tcp, HTTP: http, Ping: ping}
	}
	ok := []generate.Probes{
		p([]generate.TCPProbe{{Name: "a", Host: "db.example.com", Port: 5432}}, nil, nil, 0),
		p([]generate.TCPProbe{{Name: "a", Host: "a.b.example.com", Port: 443}}, nil, nil, 15),
		p([]generate.TCPProbe{{Name: "a", Host: "192.0.2.7", Port: 443}}, nil, nil, 0),
		p(nil, []generate.HTTPProbe{{Name: "a", URL: "https://api.example.org/x"}}, nil, 0),
		p(nil, []generate.HTTPProbe{{Name: "a", URL: "http://192.0.2.9:5432/"}}, nil, 0),
	}
	for i, x := range ok {
		if err := x.CheckAllow(testAllow); err != nil {
			t.Errorf("ok %d: %v", i, err)
		}
	}
	bad := map[string]generate.Probes{
		"suffix only":     p([]generate.TCPProbe{{Name: "a", Host: "example.com", Port: 443}}, nil, nil, 0),
		"look-alike":      p([]generate.TCPProbe{{Name: "a", Host: "evilexample.com", Port: 443}}, nil, nil, 0),
		"other domain":    p([]generate.TCPProbe{{Name: "a", Host: "x.example.net", Port: 443}}, nil, nil, 0),
		"ip outside":      p([]generate.TCPProbe{{Name: "a", Host: "198.51.100.1", Port: 443}}, nil, nil, 0),
		"port":            p([]generate.TCPProbe{{Name: "a", Host: "db.example.com", Port: 22}}, nil, nil, 0),
		"http port 80":    p(nil, []generate.HTTPProbe{{Name: "a", URL: "http://api.example.org/"}}, nil, 0),
		"interval":        p([]generate.TCPProbe{{Name: "a", Host: "db.example.com", Port: 443}}, nil, nil, 10),
		"ping not on":     p(nil, nil, []generate.PingProbe{{Name: "a", Host: "db.example.com"}}, 0),
		"too many probes": p([]generate.TCPProbe{{Name: "a", Host: "a.example.com", Port: 443}, {Name: "b", Host: "b.example.com", Port: 443}, {Name: "c", Host: "c.example.com", Port: 443}, {Name: "d", Host: "d.example.com", Port: 443}, {Name: "e", Host: "e.example.com", Port: 443}, {Name: "f", Host: "f.example.com", Port: 443}}, nil, nil, 0),
	}
	for name, x := range bad {
		if err := x.CheckAllow(testAllow); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	al := testAllow
	al.Ping = true
	if err := p(nil, nil, []generate.PingProbe{{Name: "a", Host: "db.example.com"}}, 0).CheckAllow(al); err != nil {
		t.Errorf("ping allowed: %v", err)
	}
}

// fakeRun records commands; configtest fails when the staged config contains "fail_me".
type fakeRun struct{ calls []string }

func (f *fakeRun) run(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, filepath.Base(name)+" "+strings.Join(args, " "))
	if len(args) == 2 && args[0] == "--configtest" {
		b, _ := os.ReadFile(strings.TrimPrefix(args[1], "--config_file="))
		if strings.Contains(string(b), "fail_me") {
			return []byte("bad config"), errors.New("exit 1")
		}
	}
	return nil, nil
}

func setupPrefix(t *testing.T, cpKey string, url string) string {
	t.Helper()
	pre := t.TempDir()
	for _, d := range []string{"agent", "config/cloudprober", "bin"} {
		if err := os.MkdirAll(filepath.Join(pre, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ans := "probes:\n  http:\n    - {name: local_web, url: \"https://www.example.com/\"}\nagent:\n  url: " + url +
		"\n  control_plane_key: \"" + cpKey + "\"\n  allow:\n    domains: [\"*.example.com\"]\n    ports: [443, 5432]\n"
	if err := os.WriteFile(filepath.Join(pre, "answers.yaml"), []byte(ans), 0o644); err != nil {
		t.Fatal(err)
	}
	return pre
}

func TestApplyWritesStagesAndRestartsOnlyOnConfigChange(t *testing.T) {
	pre := setupPrefix(t, "ed25519:"+base64.StdEncoding.EncodeToString(make([]byte, 32)), "https://cp.example.com/agent/")
	f := &fakeRun{}
	a := &Applier{Prefix: pre, Run: f.run}
	local := generate.Probes{HTTP: []generate.HTTPProbe{{Name: "local_web", URL: "https://www.example.com/"}}}
	remote := generate.Probes{TCP: []generate.TCPProbe{{Name: "link_a_b", Host: "db.example.com", Port: 5432}}}
	restarted, err := a.Apply(local, remote)
	if err != nil || !restarted {
		t.Fatalf("first apply: %v restarted=%v", err, restarted)
	}
	cfg, _ := os.ReadFile(filepath.Join(pre, "config/cloudprober/cloudprober.cfg"))
	if !strings.Contains(string(cfg), filepath.ToSlash(pre)+"/config/cloudprober/cloudprober-tcp.json") || !strings.Contains(string(cfg), "http_local_web") {
		t.Fatalf("config:\n%s", cfg)
	}
	tcp, _ := os.ReadFile(filepath.Join(pre, "config/cloudprober/cloudprober-tcp.json"))
	if !strings.Contains(string(tcp), `"target": "link_a_b"`) {
		t.Fatalf("targets: %s", tcp)
	}
	// same config, other tcp target: only the target file changes, no restart
	remote.TCP[0].Host = "db2.example.com"
	f.calls = nil
	if restarted, err = a.Apply(local, remote); err != nil || restarted {
		t.Fatalf("target-only change: %v restarted=%v (%v)", err, restarted, f.calls)
	}
	// configtest fails: nothing installed changes
	before, _ := os.ReadFile(filepath.Join(pre, "config/cloudprober/cloudprober-tcp.json"))
	_, err = a.Apply(local, generate.Probes{HTTP: []generate.HTTPProbe{{Name: "fail_me", URL: "https://x.example.com/"}}})
	var rej *Reject
	if !errors.As(err, &rej) || !strings.Contains(err.Error(), "configtest") {
		t.Fatalf("configtest failure: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(pre, "config/cloudprober/cloudprober-tcp.json"))
	if string(before) != string(after) {
		t.Fatal("a failed configtest changed the installed files")
	}
	// remote name = a local name: rejected
	if _, err := a.Apply(local, generate.Probes{HTTP: []generate.HTTPProbe{{Name: "local_web", URL: "https://y.example.com/"}}}); !errors.As(err, &rej) {
		t.Fatalf("duplicate name: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(pre, "config/cloudprober"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("stage left: %s", e.Name())
		}
	}
}
