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

const settingsOn = "  settings:\n    allow: [services_edit, rescan]\n"

// v0.35.0: the wire format of the agent settings, signed like the rest, read strictly
func TestDocSettingsRoundTrip(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	sign := func(set any) []byte {
		doc := map[string]any{"host": "app-1", "revision": 4, "issued_at": now.Unix(), "expires_at": now.Unix() + 60,
			"probes": map[string]any{}, "settings": map[string]any{"revision": 3, "set": set}}
		b, _ := json.Marshal(doc)
		c, err := agent.CanonicalJSON(b)
		if err != nil {
			t.Fatal(err)
		}
		doc["sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, c))
		raw, _ := json.Marshal(doc)
		return raw
	}
	d, err := agent.VerifySigned(sign(map[string]bool{"rescan": true, "docker": false}), priv.Public().(ed25519.PublicKey), "app-1", 0, now)
	if err != nil || d.Settings == nil || d.Settings.Revision != 3 || d.Settings.Set.String() != "docker off, rescan on" {
		t.Fatalf("%v %+v", err, d.Settings)
	}
	b, _ := json.Marshal(generate.SettingsOverlay{Revision: 3, Set: generate.SettingsSet{"rescan": true}})
	if string(b) != `{"revision":3,"set":{"rescan":true}}` {
		t.Errorf("marshal: %s", b)
	}
	if _, err := agent.VerifySigned(sign(map[string]any{"rescan": "yes"}), priv.Public().(ed25519.PublicKey), "app-1", 0, now); err == nil {
		t.Error("a non-bool value was accepted")
	}
}

// the set is handed to root once per revision, root's result reported once; the inventory carries consent, pins
// and the installed set, and the switches it reports are the effective ones
func TestSettingsRequestHandedOnce(t *testing.T) {
	cp, pre, f := startAgent(t, settingsOn+"  disk_scan:\n    allow: false\n", "v0.35.0")
	rev := cp.PublishSettings("app-1", dbProbe, 2, map[string]bool{"services_edit": true}, nil)
	s := waitStatuses(t, cp, 1)[0]
	if s.Result != "applied" || s.Revision != rev || s.Settings == nil || s.Settings.Result != "started" || s.Settings.Revision != 2 || s.Services != nil {
		t.Fatalf("settings status: %+v %+v", s, s.Settings)
	}
	if f.count(startCmd) != 1 {
		t.Errorf("unit start: %q", f.calls)
	}
	raw, err := os.ReadFile(filepath.Join(pre, filepath.FromSlash(agent.UpdateRequestFile)))
	if err != nil {
		t.Fatal(err)
	}
	var d agent.Doc
	if err := json.Unmarshal(raw, &d); err != nil || d.Sig == "" || d.Settings == nil || d.Settings.Revision != 2 {
		t.Errorf("request file is not the signed document: %v %s", err, raw)
	}
	cp.PublishSettings("app-1", dbProbe, 2, map[string]bool{"services_edit": true}, nil)
	if s := waitStatuses(t, cp, 2)[1]; s.Settings != nil {
		t.Errorf("repeated set: %+v", s.Settings)
	}
	b, _ := json.Marshal(agent.SettingsResult{Revision: 2, DocRevision: rev, Result: "applied", Detail: "done", At: 1})
	if err := os.WriteFile(filepath.Join(pre, filepath.FromSlash(agent.SettingsResultFile)), b, 0o644); err != nil {
		t.Fatal(err)
	}
	s = waitStatuses(t, cp, 3)[2]
	if s.Settings == nil || s.Settings.Result != "applied" || s.Settings.Revision != 2 {
		t.Fatalf("result status: %+v %+v", s, s.Settings)
	}
	time.Sleep(800 * time.Millisecond)
	if n := len(cp.Statuses()); n != 3 {
		t.Errorf("the result was reported %d times", n-2)
	}
	// services switches and settings in one document: the services first, the settings with the next document
	svc := map[string]any{"services": map[string]any{"revision": 1, "set": map[string]any{}}}
	if err := os.WriteFile(filepath.Join(pre, "answers.yaml"), append(mustRead(t, filepath.Join(pre, "answers.yaml")), servicesOn...), 0o644); err != nil {
		t.Fatal(err)
	}
	cp.PublishSettings("app-1", dbProbe, 3, map[string]bool{}, svc)
	if s := waitStatuses(t, cp, 4)[3]; s.Services == nil || s.Settings != nil {
		t.Fatalf("services first: %+v %+v %+v", s, s.Services, s.Settings)
	}
	cp.PublishSettings("app-1", dbProbe, 3, map[string]bool{}, svc)
	if s := waitStatuses(t, cp, 5)[4]; s.Services != nil || s.Settings == nil || s.Settings.Revision != 3 || s.Settings.Result != "started" {
		t.Fatalf("then the settings: %+v %+v %+v", s, s.Services, s.Settings)
	}
	if st, _ := agent.LoadState(pre); st.SettingsRevision != 3 || st.SettingsReported != 2 {
		t.Errorf("state: %+v", st)
	}
	invs, _ := cp.Inventories()
	if len(invs) == 0 || strings.Join(invs[0].SettingsEdit, ",") != "rescan,services_edit" || strings.Join(invs[0].SettingsPinned, ",") != "disk_scan" ||
		invs[0].SettingsCP == nil || invs[0].SettingsCP.Revision != 0 || invs[0].SettingsCP.Set == nil || invs[0].ServicesEdit {
		t.Errorf("inventory settings: %+v", invs)
	}
	// root installed a set: the inventory reports it and the effective switch
	ov, _ := generate.MarshalSettingsOverlay(generate.SettingsOverlay{Revision: 3, Set: generate.SettingsSet{"services_edit": true}})
	if err := os.WriteFile(filepath.Join(pre, filepath.FromSlash(generate.SettingsFile)), ov, 0o644); err != nil {
		t.Fatal(err)
	}
	seen := false
	for i := 0; i < 100 && !seen; i++ {
		invs, _ := cp.Inventories()
		for _, inv := range invs {
			seen = seen || (inv.SettingsCP != nil && inv.SettingsCP.Revision == 3 && inv.SettingsCP.Set["services_edit"] && inv.ServicesEdit)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !seen {
		t.Error("the inventory never reported the installed set with the effective switch")
	}
}

// v0.35.1: a set that arrives while the root unit still runs an earlier job waits (not lost) and starts after it.
func TestSettingsWaitWhileRootBusy(t *testing.T) {
	f := &lockedRun{busy: true}
	cp, _, _ := startAgentRun(t, settingsOn, "v0.35.0", f)
	cp.PublishSettings("app-1", dbProbe, 2, map[string]bool{"services_edit": true}, nil)
	time.Sleep(900 * time.Millisecond)
	if n := f.count(startCmd); n != 0 {
		t.Fatalf("root unit started while busy: %q", f.calls)
	}
	for _, s := range cp.Statuses() {
		if s.Settings != nil {
			t.Fatalf("settings handled while busy: %+v", s.Settings)
		}
	}
	f.setBusy(false)
	for i := 0; i < 100 && f.count(startCmd) == 0; i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if n := f.count(startCmd); n != 1 {
		t.Fatalf("root unit starts after the earlier job: %d %q", n, f.calls)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSettingsRequestRefusedByTheAgent(t *testing.T) {
	cases := []struct {
		name, policy string
		set          map[string]bool
		want         string
	}{
		{"no consent (default)", "", map[string]bool{"rescan": true}, "agent.settings.allow"},
		{"unknown key", settingsOn, map[string]bool{"update": true}, `unknown key "update"`},
		{"not in the consent list", settingsOn, map[string]bool{"docker": true}, "docker is not in"},
		{"pinned", settingsOn + "  rescan:\n    allow: true\n", map[string]bool{"rescan": false}, "rescan is pinned"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cp, pre, f := startAgent(t, c.policy, "v0.35.0")
			cp.PublishSettings("app-1", dbProbe, 1, c.set, nil)
			s := waitStatuses(t, cp, 1)[0]
			if s.Result != "applied" || s.Settings == nil || s.Settings.Result != "refused" || !strings.Contains(s.Settings.Detail, c.want) {
				t.Fatalf("status: %+v %+v", s, s.Settings)
			}
			if _, err := os.Stat(filepath.Join(pre, filepath.FromSlash(agent.UpdateRequestFile))); err == nil || f.count(startCmd) != 0 {
				t.Error("a refused set was handed to root")
			}
			invs, _ := cp.Inventories()
			if c.policy == "" && len(invs) > 0 && (invs[0].SettingsEdit != nil || invs[0].SettingsCP != nil || invs[0].SettingsPinned == nil) {
				t.Errorf("no consent: inventory %+v", invs[0])
			}
		})
	}
}

// v0.36.0: values travel in the signed document; an unknown group does not reject the document (the probes go on),
// the agent refuses the set; the inventory reports the effective values and the installed values
func TestSettingsValuesFromTheConsole(t *testing.T) {
	cp, pre, f := startAgent(t, "  settings:\n    allow: [checks, tomcat]\nservices:\n  tomcat:\n    time_zone: UTC\n", "v0.36.0")
	set := func(rev int, v map[string]any) map[string]any {
		return map[string]any{"settings": map[string]any{"revision": rev, "set": map[string]bool{}, "values": v}}
	}
	checks := map[string]any{"http": []any{map[string]any{"url": "https://app.example.com/", "comment": "app"}}, "tcp": []any{}}
	rev := cp.PublishSettings("app-1", dbProbe, 0, nil, set(1, map[string]any{"checks": checks}))
	s := waitStatuses(t, cp, 1)[0]
	if s.Result != "applied" || s.Revision != rev || s.Settings == nil || s.Settings.Result != "started" || f.count(startCmd) != 1 {
		t.Fatalf("values: %+v %+v %q", s, s.Settings, f.calls)
	}
	for _, c := range []struct {
		v      map[string]any
		detail string
	}{
		{map[string]any{"checks": checks, "redis": map[string]any{}}, "redis: unknown group"},
		{map[string]any{"tomcat": map[string]any{"logs": []any{}, "time_zone": "", "login_path": ""}}, "tomcat is pinned"},
		{map[string]any{"checks": map[string]any{"http": []any{map[string]any{"url": "https://u:p@app.example.com/"}}, "tcp": []any{}}}, "contains credentials"},
	} {
		n := len(cp.Statuses())
		cp.PublishSettings("app-1", dbProbe, 0, nil, set(2+n, c.v))
		s := waitStatuses(t, cp, n+1)[n]
		if s.Result != "applied" || s.Settings == nil || s.Settings.Result != "refused" || !strings.Contains(s.Settings.Detail, c.detail) {
			t.Errorf("%s: %+v %+v", c.detail, s, s.Settings)
		}
	}
	if f.count(startCmd) != 1 {
		t.Errorf("a refused set started root: %q", f.calls)
	}
	// root installed checks: the inventory shows the installed values and the effective ones
	ov := generate.SettingsOverlay{Revision: 1, Set: generate.SettingsSet{}, Values: &generate.SettingsValues{Checks: &generate.ChecksValue{
		HTTP: []generate.HTTPCheck{{URL: "https://app.example.com/", Comment: "app"}}, TCP: []generate.TCPCheck{}}}}
	b, _ := generate.MarshalSettingsOverlay(ov)
	if err := os.WriteFile(filepath.Join(pre, filepath.FromSlash(generate.SettingsFile)), b, 0o644); err != nil {
		t.Fatal(err)
	}
	seen, last := false, ""
	for i := 0; i < 100 && !seen; i++ {
		invs, _ := cp.Inventories()
		for _, inv := range invs {
			b, _ := json.Marshal(map[string]any{"cp": inv.SettingsCP, "values": inv.SettingsValues, "pinned": inv.SettingsPinned})
			last = string(b)
			seen = seen || last == `{"cp":{"revision":1,"set":{},"values":{"checks":{"http":[{"url":"https://app.example.com/","comment":"app"}],"tcp":[]}}},`+
				`"pinned":["tomcat"],"values":{"checks":{"http":[{"url":"https://app.example.com/","comment":"app"}],"tcp":[]},`+
				`"oracle":{"service":"","user":"","capacity":false,"capacity_pdbs":[]},"tomcat":{"logs":[],"time_zone":"UTC","login_path":""}}}`
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !seen {
		t.Errorf("inventory never carried the values: %s", last)
	}
}
