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

const servicesOn = "  services_edit:\n    allow: true\n"

func redisOn(port int) map[string]any {
	return map[string]any{"redis": map[string]any{"on": true, "port": port}}
}

// v0.33.0: the wire format of the service switches, signed like the rest, read strictly
func TestDocServicesRoundTrip(t *testing.T) {
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
	doc := func(set map[string]any) map[string]any {
		return map[string]any{"host": "app-1", "revision": 4, "issued_at": now.Unix(), "expires_at": now.Unix() + 60,
			"probes": map[string]any{}, "services": map[string]any{"revision": 3, "set": set}}
	}
	set := map[string]any{"redis": map[string]any{"on": true, "port": 6380}, "nginx": map[string]any{"on": true, "port": 80, "status_path": "/nginx_status"}}
	d, err := agent.VerifySigned(sign(doc(set)), priv.Public().(ed25519.PublicKey), "app-1", 0, now)
	if err != nil || d.Services == nil || d.Services.Revision != 3 || d.Services.Set.String() != "nginx on :80 /nginx_status, redis on :6380" {
		t.Fatalf("%v %+v", err, d.Services)
	}
	b, _ := json.Marshal(generate.ServicesOverlay{Revision: 3, Set: generate.ServicesSet{"redis": {On: true, Port: 6380}}})
	if string(b) != `{"revision":3,"set":{"redis":{"on":true,"port":6380}}}` {
		t.Errorf("marshal: %s", b)
	}
	bad := map[string]any{"redis": map[string]any{"on": true, "port": 6380, "command": "x"}}
	if _, err := agent.VerifySigned(sign(doc(bad)), priv.Public().(ed25519.PublicKey), "app-1", 0, now); err == nil {
		t.Error("an unknown key in a switch was accepted")
	}
}

// the set is handed to root once per revision, root's result reported once; the inventory carries the switch + set
func TestServicesRequestHandedOnce(t *testing.T) {
	cp, pre, f := startAgent(t, servicesOn, "v0.33.0")
	rev := cp.PublishServices("app-1", dbProbe, 2, redisOn(6380), nil)
	s := waitStatuses(t, cp, 1)[0]
	if s.Result != "applied" || s.Revision != rev || s.Services == nil || s.Services.Result != "started" || s.Services.Revision != 2 || s.Allow != nil || s.Update != nil {
		t.Fatalf("services status: %+v %+v", s, s.Services)
	}
	if f.count(startCmd) != 1 {
		t.Errorf("unit start: %q", f.calls)
	}
	raw, err := os.ReadFile(filepath.Join(pre, filepath.FromSlash(agent.UpdateRequestFile)))
	if err != nil {
		t.Fatal(err)
	}
	var d agent.Doc
	if err := json.Unmarshal(raw, &d); err != nil || d.Sig == "" || d.Services == nil || d.Services.Revision != 2 || d.Revision != rev {
		t.Errorf("request file is not the signed document: %v %s", err, raw)
	}
	// the same revision again: not handed again
	cp.PublishServices("app-1", dbProbe, 2, redisOn(6380), nil)
	if s := waitStatuses(t, cp, 2)[1]; s.Services != nil {
		t.Errorf("repeated set: %+v", s.Services)
	}
	// root's result: reported once
	b, _ := json.Marshal(agent.ServicesResult{Revision: 2, DocRevision: rev, Result: "applied", Detail: "done", At: 1})
	if err := os.WriteFile(filepath.Join(pre, filepath.FromSlash(agent.ServicesResultFile)), b, 0o644); err != nil {
		t.Fatal(err)
	}
	s = waitStatuses(t, cp, 3)[2]
	if s.Services == nil || s.Services.Result != "applied" || s.Services.Revision != 2 {
		t.Fatalf("result status: %+v %+v", s, s.Services)
	}
	time.Sleep(800 * time.Millisecond)
	if n := len(cp.Statuses()); n != 3 {
		t.Errorf("the result was reported %d times", n-2)
	}
	// a new update and a new set in one document: the update goes first, the set with the next document
	upd := map[string]any{"update": map[string]any{"version": "v0.33.1", "id": "u-0123456789"}}
	cp.PublishServices("app-1", dbProbe, 3, redisOn(6380), upd)
	if s := waitStatuses(t, cp, 4)[3]; s.Update == nil || s.Services != nil {
		t.Fatalf("update first: %+v %+v %+v", s, s.Update, s.Services)
	}
	cp.PublishServices("app-1", dbProbe, 3, redisOn(6380), upd)
	if s := waitStatuses(t, cp, 5)[4]; s.Update != nil || s.Services == nil || s.Services.Revision != 3 || s.Services.Result != "started" {
		t.Fatalf("then the set: %+v %+v %+v", s, s.Update, s.Services)
	}
	if st, _ := agent.LoadState(pre); st.ServicesRevision != 3 || st.ServicesReported != 2 {
		t.Errorf("state: %+v", st)
	}
	invs, _ := cp.Inventories()
	if len(invs) == 0 || !invs[0].ServicesEdit || invs[0].ServicesCP == nil || invs[0].ServicesCP.Revision != 0 || invs[0].ServicesCP.Set == nil {
		t.Errorf("inventory services_edit / services_cp: %+v", invs)
	}
	// root installed a set: the inventory reports it
	ov, _ := generate.MarshalServicesOverlay(generate.ServicesOverlay{Revision: 3, Set: generate.ServicesSet{"redis": {On: true, Port: 6380}}})
	if err := os.WriteFile(filepath.Join(pre, filepath.FromSlash(generate.ServicesFile)), ov, 0o644); err != nil {
		t.Fatal(err)
	}
	seen := false
	for i := 0; i < 100 && !seen; i++ {
		invs, _ := cp.Inventories()
		for _, inv := range invs {
			seen = seen || (inv.ServicesCP != nil && inv.ServicesCP.Revision == 3 && inv.ServicesCP.Set["redis"].Port == 6380)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !seen {
		t.Error("the inventory never reported the installed set")
	}
}

func TestServicesRequestRefusedByTheAgent(t *testing.T) {
	cases := []struct {
		name, policy string
		set          map[string]any
		want         string
	}{
		{"switch off (default)", "", redisOn(6380), "agent.services_edit.allow"},
		{"kind not in the list", servicesOn, map[string]any{"docker": map[string]any{"on": true, "port": 2375}}, `kind "docker"`},
		{"bad status path", servicesOn, map[string]any{"nginx": map[string]any{"on": true, "port": 80, "status_path": "/a b"}}, "status_path"},
		{"status path for redis", servicesOn, map[string]any{"redis": map[string]any{"on": true, "port": 6379, "status_path": "/x"}}, "nginx setting"},
		{"port out of range", servicesOn, redisOn(0), "port 0"},
		{"locked in the answers", "services:\n  redis:\n    enabled: false\n    locked: true\n", redisOn(6380), "locked"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			policy := c.policy
			if strings.HasPrefix(policy, "services:") {
				policy = servicesOn + policy // the agent section is the answers' last: a top-level key after it
			}
			cp, pre, f := startAgent(t, policy, "v0.33.0")
			cp.PublishServices("app-1", dbProbe, 1, c.set, nil)
			s := waitStatuses(t, cp, 1)[0]
			if s.Result != "applied" || s.Services == nil || s.Services.Result != "refused" || !strings.Contains(s.Services.Detail, c.want) {
				t.Fatalf("status: %+v %+v", s, s.Services)
			}
			if _, err := os.Stat(filepath.Join(pre, filepath.FromSlash(agent.UpdateRequestFile))); err == nil || f.count("systemctl start") != 0 {
				t.Error("a refused set was handed to root")
			}
		})
	}
}
