package generate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var editOn = AgentAllowEdit{Allow: true, Ping: true, MaxProbes: 50}

// base: what the template + answers extras give (defaults filled in)
var editBase = Allow{Domains: []string{"*.example.com"}, Ports: []int{443}}.Merge(Allow{})

func TestCheckAllowOverlay(t *testing.T) {
	long := make([]string, OverlayMaxList+1)
	for i := range long {
		long[i] = "h" + strings.Repeat("x", i%5) + ".example.org"
	}
	ports := make([]int, OverlayMaxList+1)
	for i := range ports {
		ports[i] = 1000 + i
	}
	ok := []Allow{
		{},
		{Domains: []string{"db.example.net", "*.example.org"}, Networks: []string{"192.0.2.0/24", "198.51.0.0/16", "2001:db8::/48"}, Ports: []int{1, 5432, 65535}},
		{MaxProbes: 50, MinIntervalS: 15, Ping: true},
		{Networks: []string{"::ffff:192.0.2.0/120"}}, // an IPv4-mapped /24
	}
	for _, a := range ok {
		if err := CheckAllowOverlay(a, editOn, editBase); err != nil {
			t.Errorf("%+v: %v", a, err)
		}
	}
	bad := map[string]struct {
		a    Allow
		edit AgentAllowEdit
		want string
	}{
		"switch off":         {Allow{Ports: []int{22}}, AgentAllowEdit{}, "allow_edit.allow"},
		"domain pattern":     {Allow{Domains: []string{"DB.example.com"}}, editOn, "domain"},
		"domain with path":   {Allow{Domains: []string{"example.com/x"}}, editOn, "domain"},
		"too many domains":   {Allow{Domains: long}, editOn, "at most 64"},
		"too many ports":     {Allow{Ports: ports}, editOn, "at most 64"},
		"not a CIDR":         {Allow{Networks: []string{"192.0.2.1"}}, editOn, "CIDR"},
		"IPv4 too wide":      {Allow{Networks: []string{"10.0.0.0/8"}}, editOn, "/16"},
		"IPv4 default route": {Allow{Networks: []string{"0.0.0.0/0"}}, editOn, "/16"},
		"IPv6 too wide":      {Allow{Networks: []string{"2001:db8::/32"}}, editOn, "/48"},
		"IPv6 default route": {Allow{Networks: []string{"::/0"}}, editOn, "/48"},
		"mapped IPv4 /0":     {Allow{Networks: []string{"::ffff:0:0/96"}}, editOn, "/16"},
		"port 0":             {Allow{Ports: []int{0}}, editOn, "port 0"},
		"port 65536":         {Allow{Ports: []int{65536}}, editOn, "port 65536"},
		"max_probes ceiling": {Allow{MaxProbes: 51}, editOn, "ceiling 50"},
		"ceiling = base":     {Allow{MaxProbes: 31}, AgentAllowEdit{Allow: true}, "ceiling 30"},
		"max_probes 101":     {Allow{MaxProbes: 101}, AgentAllowEdit{Allow: true, MaxProbes: 100}, "max_probes 101"},
		"max_probes < 0":     {Allow{MaxProbes: -1}, editOn, "max_probes -1"},
		"interval below 15":  {Allow{MinIntervalS: 10}, editOn, "min_interval_s 10"},
		"ping not allowed":   {Allow{Ping: true}, AgentAllowEdit{Allow: true}, "allow_edit.ping"},
	}
	for name, c := range bad {
		if err := CheckAllowOverlay(c.a, c.edit, editBase); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", name, err, c.want)
		}
	}
}

func TestEffectiveAllow(t *testing.T) {
	ov := Allow{Domains: []string{"db.example.net", "*.example.com"}, Networks: []string{"192.0.2.0/24"}, Ports: []int{5432, 443},
		MaxProbes: 80, MinIntervalS: 30, Ping: true}
	got := EffectiveAllow(editBase, editOn, ov)
	want := "domains *.example.com,db.example.net; networks 192.0.2.0/24; ports 443,5432; max 50 probes; interval >= 30 s; ping true"
	if got.String() != want {
		t.Errorf("effective:\n got %s\nwant %s", got, want)
	}
	// ceiling 0 = the value without the overlay; ping only with allow_edit.ping
	if got := EffectiveAllow(editBase, AgentAllowEdit{Allow: true}, ov); got.MaxProbes != 30 || got.Ping {
		t.Errorf("no ceiling / no ping: %s", got)
	}
	// lower than the base is allowed (a non-zero number replaces)
	if got := EffectiveAllow(editBase, editOn, Allow{MaxProbes: 10}); got.MaxProbes != 10 || got.MinIntervalS != 15 {
		t.Errorf("lower max_probes: %s", got)
	}
	// switched off: an installed overlay is ignored
	if got := EffectiveAllow(editBase, AgentAllowEdit{}, ov); got.String() != editBase.String() {
		t.Errorf("switch off: %s", got)
	}
	if got := EffectiveAllow(editBase, editOn, Allow{}); got.String() != editBase.String() {
		t.Errorf("empty overlay: %s", got)
	}
	// never above 100, whatever the base
	if got := EffectiveAllow(Allow{MaxProbes: 100}.Merge(Allow{}), AgentAllowEdit{Allow: true}, Allow{MaxProbes: 100}); got.MaxProbes != 100 {
		t.Errorf("cap: %s", got)
	}
}

func TestAllowOverlayFileRoundTrip(t *testing.T) {
	pre := t.TempDir()
	if err := os.MkdirAll(filepath.Join(pre, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	ov := Allow{Domains: []string{"db.example.net"}, Networks: []string{"192.0.2.0/24"}, Ports: []int{5432}, MaxProbes: 40, Ping: true}
	b, err := MarshalAllowOverlay(ov, 7)
	if err != nil || !strings.Contains(string(b), "revision 7") || !strings.Contains(string(b), "max_probes: 40") {
		t.Fatalf("%v\n%s", err, b)
	}
	p := filepath.Join(pre, filepath.FromSlash(AllowOverlayFile))
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAllowOverlay(p)
	if err != nil || got.String() != ov.String() {
		t.Fatalf("round trip: %v %s", err, got)
	}
	// the template format: the template loader reads it too
	if tmpl, err := LoadAllow(p); err != nil || tmpl.String() != ov.String() {
		t.Errorf("template loader: %v %s", err, tmpl)
	}
	ag := Agent{Allow: Allow{Ports: []int{443}}, AllowEdit: AgentAllowEdit{Allow: true, MaxProbes: 35}}
	base, eff, err := LocalAllow(Allow{Domains: []string{"*.example.com"}}, ag, pre)
	if err != nil || len(base.Ports) != 1 || eff.MaxProbes != 35 || eff.Ping || len(eff.Ports) != 2 {
		t.Errorf("local: %v base %s eff %s", err, base, eff)
	}
	// strict: unknown keys and a too wide network are errors
	for _, s := range []string{"url: https://x.example.com/\n", "networks: [10.0.0.0/8]\n"} {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadAllowOverlay(p); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	// missing = none
	if got, err := LoadAllowOverlay(filepath.Join(pre, "none.yaml")); err != nil || !got.Empty() {
		t.Errorf("missing: %v %+v", err, got)
	}
}

func TestAnswersAllowEdit(t *testing.T) {
	const head = "agent:\n  url: https://agent.example.com/agent/\n  control_plane_key: \"ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\n"
	load := func(s string) (Answers, error) {
		p := filepath.Join(t.TempDir(), "answers.yaml")
		if err := os.WriteFile(p, []byte(head+s), 0o644); err != nil {
			t.Fatal(err)
		}
		return LoadAnswers(p)
	}
	a, err := load("  allow_edit:\n    allow: true\n    ping: true\n    max_probes: 50\n")
	if err != nil || a.Agent.AllowEdit != (AgentAllowEdit{Allow: true, Ping: true, MaxProbes: 50}) {
		t.Fatalf("%v %+v", err, a.Agent)
	}
	b, err := a.Marshal()
	if err != nil || !strings.Contains(string(b), "allow_edit:") {
		t.Errorf("marshal: %v\n%s", err, b)
	}
	if a, err := load(""); err != nil || a.Agent.AllowEdit.Allow {
		t.Errorf("missing = off: %v %+v", err, a.Agent)
	}
	for _, s := range []string{"  allow_edit:\n    allow: true\n    networks: [192.0.2.0/24]\n", "  allow_edit:\n    max_probes: 101\n"} {
		if _, err := load(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}
