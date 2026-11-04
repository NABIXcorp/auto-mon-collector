package agent_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/agent/agenttest"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

// lockedRun records commands (the agent runs them in its own goroutine).
type lockedRun struct {
	mu    sync.Mutex
	calls []string
}

func (f *lockedRun) run(name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, filepath.Base(name)+" "+strings.Join(args, " "))
	return nil, nil
}

func (f *lockedRun) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

const startCmd = "systemctl start --no-block monitoring-update.service"

var dbProbe = generate.Probes{TCP: []generate.TCPProbe{{Name: "link_web_db", Host: "db.example.com", Port: 5432}}}

// startAgent: a fake control plane, an enrolled agent with `policy` appended to its agent section.
func startAgent(t *testing.T, policy, running string) (*agenttest.Server, string, *lockedRun) {
	t.Helper()
	cp := agenttest.New()
	cp.Poll = 200 * time.Millisecond
	srv := httptest.NewServer(cp)
	t.Cleanup(srv.Close)
	pre := setupPrefix(t, cp.PublicKey(), srv.URL+"/agent/")
	ans, _ := os.ReadFile(filepath.Join(pre, "answers.yaml"))
	if err := os.WriteFile(filepath.Join(pre, "answers.yaml"), append(ans, policy...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := agent.Enrol(context.Background(), pre, "app-1", agenttest.Token, os.Getuid(), os.Getgid(), nil); err != nil {
		t.Fatal(err)
	}
	f := &lockedRun{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = agent.Run(ctx, agent.Config{Prefix: pre, Host: "app-1", Run: f.run, Versions: map[string]string{agent.VersionKey: running},
			NotEnrolledWait: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond})
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		srv.CloseClientConnections()
		<-done
	})
	return cp, pre, f
}

func waitStatuses(t *testing.T, cp *agenttest.Server, n int) []agent.Status {
	t.Helper()
	for i := 0; i < 250; i++ {
		if s := cp.Statuses(); len(s) >= n {
			return s
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no status %d: %+v", n, cp.Statuses())
	return nil
}

func TestUpdateRequestHandledOnce(t *testing.T) {
	cp, pre, f := startAgent(t, "  update:\n    allow: true\n", "v0.16.0")
	// a document without update: as before (no request file, no unit started)
	cp.Publish("app-1", 0, dbProbe, 0, false, false)
	if s := waitStatuses(t, cp, 1); s[0].Result != "applied" || s[0].Update != nil {
		t.Fatalf("plain document: %+v", s[0])
	}
	req := filepath.Join(pre, filepath.FromSlash(agent.UpdateRequestFile))
	if _, err := os.Stat(req); err == nil || f.count("systemctl start") != 0 {
		t.Fatal("a document without update started an update")
	}
	// a new update id: the whole signed document saved, the root unit started (no wait), "started" reported
	rev := cp.PublishUpdate("app-1", dbProbe, "v0.16.1", "u-0123456789")
	s := waitStatuses(t, cp, 2)[1]
	if s.Result != "applied" || s.Revision != rev || s.Update == nil || s.Update.Result != "started" ||
		s.Update.ID != "u-0123456789" || s.Update.From != "v0.16.0" || s.Update.To != "v0.16.1" {
		t.Fatalf("update status: %+v %+v", s, s.Update)
	}
	if f.count(startCmd) != 1 {
		t.Errorf("unit start: %q", f.calls)
	}
	raw, err := os.ReadFile(req)
	if err != nil {
		t.Fatal(err)
	}
	var d agent.Doc
	if err := json.Unmarshal(raw, &d); err != nil || d.Sig == "" || d.Update == nil || d.Update.ID != "u-0123456789" || d.Revision != rev {
		t.Errorf("request file is not the signed document: %v %s", err, raw)
	}
	if st, _ := agent.LoadState(pre); st.UpdateID != "u-0123456789" || st.Revision != rev {
		t.Errorf("state: %+v", st)
	}
	// the same id again in a newer revision: probes applied, the update NOT started again
	cp.PublishUpdate("app-1", dbProbe, "v0.16.1", "u-0123456789")
	if s := waitStatuses(t, cp, 3)[2]; s.Result != "applied" || s.Update != nil {
		t.Errorf("repeated id: %+v %+v", s, s.Update)
	}
	if f.count(startCmd) != 1 {
		t.Errorf("repeated id started the unit again: %q", f.calls)
	}
	// root's result: reported once
	res := agent.UpdateResult{ID: "u-0123456789", From: "v0.16.0", To: "v0.16.1", Result: "ok", Detail: "done", At: 1}
	b, _ := json.Marshal(res)
	if err := os.WriteFile(filepath.Join(pre, filepath.FromSlash(agent.UpdateResultFile)), b, 0o644); err != nil {
		t.Fatal(err)
	}
	s = waitStatuses(t, cp, 4)[3]
	if s.Update == nil || s.Update.Result != "ok" || s.Update.ID != "u-0123456789" || s.Update.To != "v0.16.1" {
		t.Fatalf("result status: %+v %+v", s, s.Update)
	}
	time.Sleep(800 * time.Millisecond) // several polls
	if n := len(cp.Statuses()); n != 4 {
		t.Errorf("the result was reported %d times", n-3)
	}
	if st, _ := agent.LoadState(pre); st.UpdateReported != "u-0123456789" {
		t.Errorf("state: %+v", st)
	}
	invs, _ := cp.Inventories()
	if len(invs) == 0 || !invs[0].UpdateAllowed {
		t.Errorf("inventory: update_allowed not true: %+v", invs)
	}
}

func TestUpdateRequestRefusedByTheAgent(t *testing.T) {
	cases := []struct{ name, policy, running, version, id, want string }{
		{"allow off (default)", "", "v0.16.0", "v0.16.1", "u-0123456789", "remote update is off"},
		{"downgrade", "  update:\n    allow: true\n", "v0.16.0", "v0.15.0", "u-0123456789", "not newer"},
		{"same version", "  update:\n    allow: true\n", "v0.16.0", "v0.16.0", "u-0123456789", "not newer"},
		{"bad version", "  update:\n    allow: true\n", "v0.16.0", "latest", "u-0123456789", "release tag"},
		{"bad id", "  update:\n    allow: true\n", "v0.16.0", "v0.16.1", "x/y", "update id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cp, pre, f := startAgent(t, c.policy, c.running)
			cp.PublishUpdate("app-1", dbProbe, c.version, c.id)
			s := waitStatuses(t, cp, 1)[0]
			if s.Result != "applied" || s.Update == nil || s.Update.Result != "refused" || !strings.Contains(s.Update.Detail, c.want) {
				t.Fatalf("status: %+v %+v", s, s.Update)
			}
			if _, err := os.Stat(filepath.Join(pre, filepath.FromSlash(agent.UpdateRequestFile))); err == nil || f.count("systemctl start") != 0 {
				t.Error("a refused request was handed to root")
			}
			if c.policy == "" {
				invs, _ := cp.Inventories()
				if len(invs) == 0 || invs[0].UpdateAllowed {
					t.Errorf("inventory: update_allowed: %+v", invs)
				}
			}
		})
	}
}
