package agent_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

const editOn = "  allow_edit:\n    allow: true\n    max_probes: 50\n"

func overlay(ports []any, ping bool) map[string]any {
	return map[string]any{"domains": []any{"db.example.net"}, "networks": []any{"192.0.2.0/24"}, "ports": ports,
		"max_probes": 40, "min_interval_s": 0, "ping": ping}
}

// v0.26.0: the wire format of the allowlist overlay: the complete overlay inside "allow", signed like the rest, read
// strictly (an unknown key is refused)
func TestDocAllowRoundTrip(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sign := func(doc map[string]any) []byte {
		b, _ := json.Marshal(doc)
		c, err := agent.CanonicalJSON(b)
		if err != nil {
			t.Fatal(err)
		}
		doc["sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, c))
		raw, _ := json.Marshal(doc)
		return raw
	}
	now := time.Now()
	doc := func(allow map[string]any) map[string]any {
		return map[string]any{"host": "app-1", "revision": 4, "issued_at": now.Unix(), "expires_at": now.Unix() + 60,
			"probes": map[string]any{}, "allow": map[string]any{"revision": 3, "allow": allow}}
	}
	d, err := agent.VerifySigned(sign(doc(overlay([]any{5432}, true))), priv.Public().(ed25519.PublicKey), "app-1", 0, now)
	if err != nil || d.Allow == nil || d.Allow.Revision != 3 {
		t.Fatalf("%v %+v", err, d.Allow)
	}
	want := generate.Allow{Domains: []string{"db.example.net"}, Networks: []string{"192.0.2.0/24"}, Ports: []int{5432}, MaxProbes: 40, Ping: true}
	if d.Allow.Allow.String() != want.String() {
		t.Errorf("allow: %s", d.Allow.Allow)
	}
	b, _ := json.Marshal(agent.DocAllow{Revision: 3, Allow: generate.Allow{}})
	if string(b) != `{"revision":3,"allow":{"domains":null,"networks":null,"ports":null,"max_probes":0,"min_interval_s":0,"ping":false}}` {
		t.Errorf("marshal: %s", b)
	}
	bad := overlay(nil, false)
	bad["url"] = "https://x.example.com/"
	if _, err := agent.VerifySigned(sign(doc(bad)), priv.Public().(ed25519.PublicKey), "app-1", 0, now); err == nil {
		t.Error("an unknown key in the overlay was accepted")
	}
}

// the overlay is handed to root once per revision, root's result reported once; the inventory carries the switch
func TestAllowRequestHandedOnce(t *testing.T) {
	cp, pre, f := startAgent(t, editOn, "v0.26.0")
	rev := cp.PublishAllow("app-1", dbProbe, 2, overlay([]any{5432, 22}, false), nil)
	s := waitStatuses(t, cp, 1)[0]
	if s.Result != "applied" || s.Revision != rev || s.Allow == nil || s.Allow.Result != "started" || s.Allow.Revision != 2 || s.Site != nil || s.Update != nil {
		t.Fatalf("allow status: %+v %+v", s, s.Allow)
	}
	if f.count(startCmd) != 1 {
		t.Errorf("unit start: %q", f.calls)
	}
	raw, err := os.ReadFile(filepath.Join(pre, filepath.FromSlash(agent.UpdateRequestFile)))
	if err != nil {
		t.Fatal(err)
	}
	var d agent.Doc
	if err := json.Unmarshal(raw, &d); err != nil || d.Sig == "" || d.Allow == nil || d.Allow.Revision != 2 || d.Revision != rev {
		t.Errorf("request file is not the signed document: %v %s", err, raw)
	}
	// the same overlay revision again: not handed again
	cp.PublishAllow("app-1", dbProbe, 2, overlay([]any{5432, 22}, false), nil)
	if s := waitStatuses(t, cp, 2)[1]; s.Allow != nil {
		t.Errorf("repeated overlay: %+v", s.Allow)
	}
	// root's result: reported once
	b, _ := json.Marshal(agent.AllowResult{Revision: 2, DocRevision: rev, Result: "ok", Detail: "applied", At: 1})
	if err := os.WriteFile(filepath.Join(pre, filepath.FromSlash(agent.AllowResultFile)), b, 0o644); err != nil {
		t.Fatal(err)
	}
	s = waitStatuses(t, cp, 3)[2]
	if s.Allow == nil || s.Allow.Result != "ok" || s.Allow.Revision != 2 {
		t.Fatalf("result status: %+v %+v", s, s.Allow)
	}
	time.Sleep(800 * time.Millisecond)
	if n := len(cp.Statuses()); n != 3 {
		t.Errorf("the result was reported %d times", n-2)
	}
	// a new update and a new overlay in one document: the update goes first, the overlay with the next document
	upd := map[string]any{"update": map[string]any{"version": "v0.26.1", "id": "u-0123456789"}}
	cp.PublishAllow("app-1", dbProbe, 3, overlay([]any{5432}, false), upd)
	if s := waitStatuses(t, cp, 4)[3]; s.Update == nil || s.Update.Result != "refused" || s.Allow != nil {
		t.Fatalf("update first: %+v %+v %+v", s, s.Update, s.Allow)
	}
	cp.PublishAllow("app-1", dbProbe, 3, overlay([]any{5432}, false), upd)
	if s := waitStatuses(t, cp, 5)[4]; s.Update != nil || s.Allow == nil || s.Allow.Revision != 3 || s.Allow.Result != "started" {
		t.Fatalf("then the overlay: %+v %+v %+v", s, s.Update, s.Allow)
	}
	if st, _ := agent.LoadState(pre); st.AllowRevision != 3 || st.AllowReported != 2 {
		t.Errorf("state: %+v", st)
	}
	invs, _ := cp.Inventories()
	if len(invs) == 0 || invs[0].AllowEdit == nil || !invs[0].AllowEdit.Allow || invs[0].AllowEdit.Ping || invs[0].AllowEdit.MaxProbes != 50 {
		t.Errorf("inventory allow_edit: %+v", invs)
	}
}

func TestAllowRequestRefusedByTheAgent(t *testing.T) {
	cases := []struct {
		name, policy string
		allow        map[string]any
		want         string
	}{
		{"switch off (default)", "", overlay([]any{5432}, false), "agent.allow_edit.allow"},
		{"ping not allowed", editOn, overlay([]any{5432}, true), "allow_edit.ping"},
		{"network too wide", editOn, map[string]any{"domains": []any{}, "networks": []any{"10.0.0.0/8"}, "ports": []any{}, "max_probes": 0, "min_interval_s": 0, "ping": false}, "/16"},
		{"above the ceiling", editOn, map[string]any{"domains": []any{}, "networks": []any{}, "ports": []any{}, "max_probes": 60, "min_interval_s": 0, "ping": false}, "ceiling 50"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cp, pre, f := startAgent(t, c.policy, "v0.26.0")
			cp.PublishAllow("app-1", dbProbe, 1, c.allow, nil)
			s := waitStatuses(t, cp, 1)[0]
			if s.Result != "applied" || s.Allow == nil || s.Allow.Result != "refused" || !strings.Contains(s.Allow.Detail, c.want) {
				t.Fatalf("status: %+v %+v", s, s.Allow)
			}
			if _, err := os.Stat(filepath.Join(pre, filepath.FromSlash(agent.UpdateRequestFile))); err == nil || f.count("systemctl start") != 0 {
				t.Error("a refused overlay was handed to root")
			}
		})
	}
}

// the installed overlay counts: the inventory reports the effective allowlist, and probes inside it are applied
func TestInstalledOverlayIsEffective(t *testing.T) {
	cp, pre, _ := startAgent(t, editOn, "v0.26.0")
	b, _ := generate.MarshalAllowOverlay(generate.Allow{Networks: []string{"192.0.2.0/24"}, Ports: []int{22}}, 1)
	if err := os.WriteFile(filepath.Join(pre, filepath.FromSlash(generate.AllowOverlayFile)), b, 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := agent.LoadLocal(pre)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(l.Allow.String(), "networks 192.0.2.0/24; ports 22,443,5432") || strings.Contains(l.Base.String(), "192.0.2.0/24") {
		t.Fatalf("effective %s / base %s", l.Allow, l.Base)
	}
	// the agent reads the overlay at the start of each poll: the inventory shows when it has
	seen := false
	for i := 0; i < 100 && !seen; i++ {
		invs, _ := cp.Inventories()
		for _, inv := range invs {
			seen = seen || (inv.Allow != nil && strings.Contains(strings.Join(inv.Allow.Networks, ","), "192.0.2.0/24"))
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !seen {
		t.Fatal("the inventory never reported the overlay's network")
	}
	rev := cp.Publish("app-1", 0, generate.Probes{TCP: []generate.TCPProbe{{Name: "link_ssh", Host: "192.0.2.10", Port: 22}}}, 0, false, false)
	s := waitStatuses(t, cp, 1)[0]
	if s.Revision != rev || s.Result != "applied" {
		t.Fatalf("a probe inside the overlay: %+v", s)
	}
}
