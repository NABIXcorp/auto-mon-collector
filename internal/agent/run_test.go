package agent_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/agent/agenttest"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

type fakeRun2 struct{ calls []string }

func (f *fakeRun2) run(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, filepath.Base(name)+" "+strings.Join(args, " "))
	return nil, nil
}

var _ = errors.New

func setupPrefix(t *testing.T, cpKey string, url string) string {
	t.Helper()
	pre := t.TempDir()
	for _, d := range []string{"agent", "config/cloudprober", "bin"} {
		if err := os.MkdirAll(filepath.Join(pre, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ans := "agent:\n  url: " + url + "\n  control_plane_key: \"" + cpKey + "\"\n  allow:\n    domains: [\"*.example.com\"]\n    ports: [443, 5432]\n"
	if err := os.WriteFile(filepath.Join(pre, "answers.yaml"), []byte(ans), 0o644); err != nil {
		t.Fatal(err)
	}
	return pre
}

// End to end in process: enrol with the fake control plane, apply a list, reject a tampered one, survive a
// control plane outage.
func TestRunAgainstFakeControlPlane(t *testing.T) {
	cp := agenttest.New()
	cp.Poll = 300 * time.Millisecond
	srv := httptest.NewServer(cp)
	defer srv.Close()
	pre := setupPrefix(t, cp.PublicKey(), srv.URL+"/agent/")
	if err := agent.Enrol(context.Background(), pre, "app-1", "wrong", os.Getuid(), os.Getgid(), nil); err == nil {
		t.Fatal("wrong token accepted")
	}
	if err := agent.Enrol(context.Background(), pre, "app-1", agenttest.Token, os.Getuid(), os.Getgid(), nil); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(pre, agent.KeyFile)); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("key file: %v", err)
	}
	f := &fakeRun2{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = agent.Run(ctx, agent.Config{Prefix: pre, Host: "app-1", Run: f.run, Versions: map[string]string{"amc": "test"},
			NotEnrolledWait: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond})
		close(done)
	}()
	waitStatus := func(n int) []agent.Status {
		t.Helper()
		for i := 0; i < 200; i++ {
			if s := cp.Statuses(); len(s) >= n {
				return s
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("no status %d: %+v", n, cp.Statuses())
		return nil
	}
	cp.Publish("app-1", 0, generate.Probes{TCP: []generate.TCPProbe{{Name: "link_web_db", Host: "db.example.com", Port: 5432}}}, 0, false, false)
	if s := waitStatus(1); s[0].Result != "applied" || s[0].Revision != 1 || s[0].Versions["amc"] != "test" {
		t.Fatalf("status: %+v", s[0])
	}
	st, _ := agent.LoadState(pre)
	if st.Revision != 1 || len(st.Probes.TCP) != 1 {
		t.Fatalf("state: %+v", st)
	}
	cp.Publish("app-1", 0, generate.Probes{TCP: []generate.TCPProbe{{Name: "x", Host: "db.example.com", Port: 5432}}}, 0, true, false)
	if s := waitStatus(2); s[1].Result != "rejected" || !strings.Contains(s[1].Detail, "signature") {
		t.Fatalf("tampered: %+v", s[1])
	}
	cp.Publish("app-1", 0, generate.Probes{TCP: []generate.TCPProbe{{Name: "y", Host: "evil.example.net", Port: 5432}}}, 0, false, false)
	if s := waitStatus(3); s[2].Result != "rejected" || !strings.Contains(s[2].Detail, "allowlist") {
		t.Fatalf("outside: %+v", s[2])
	}
	if st, _ := agent.LoadState(pre); st.Revision != 1 {
		t.Fatalf("a rejected list changed the state: %+v", st)
	}
	srv.CloseClientConnections()
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not stop")
	}
}

// v0.15.0: the inventory (versions + revision + inventory.json) goes out at start and again when it changes
// (a new revision applied); a control plane without the endpoint (404) is asked once only.
func TestInventorySent(t *testing.T) {
	for _, old := range []bool{false, true} {
		cp := agenttest.New()
		cp.Poll = 200 * time.Millisecond
		cp.NoInventory = old
		srv := httptest.NewServer(cp)
		pre := setupPrefix(t, cp.PublicKey(), srv.URL+"/agent/")
		if err := os.WriteFile(filepath.Join(pre, generate.InventoryFile), []byte("{\n  \"schema\": 1,\n  \"services\": []\n}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := agent.Enrol(context.Background(), pre, "app-1", agenttest.Token, os.Getuid(), os.Getgid(), nil); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			_ = agent.Run(ctx, agent.Config{Prefix: pre, Host: "app-1", Run: (&fakeRun2{}).run,
				Versions: map[string]string{"amc": "v-test"}, NotEnrolledWait: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond})
			close(done)
		}()
		waitFor := func(what string, ok func() bool) {
			t.Helper()
			for i := 0; i < 150 && !ok(); i++ {
				time.Sleep(20 * time.Millisecond)
			}
			if !ok() {
				invs, calls := cp.Inventories()
				t.Fatalf("old=%v: %s: %d calls, %+v", old, what, calls, invs)
			}
		}
		waitFor("inventory at start", func() bool { _, n := cp.Inventories(); return n >= 1 })
		cp.Publish("app-1", 0, generate.Probes{TCP: []generate.TCPProbe{{Name: "link_web_db", Host: "db.example.com", Port: 5432}}}, 0, false, false)
		waitFor("status", func() bool { return len(cp.Statuses()) == 1 })
		if old {
			time.Sleep(600 * time.Millisecond) // a few more polls
			if _, n := cp.Inventories(); n != 2 {
				t.Errorf("404: asked at start and once after the new revision (body changed), got %d calls", n)
			}
		} else {
			waitFor("inventory after the revision", func() bool { i, _ := cp.Inventories(); return len(i) >= 2 })
			invs, _ := cp.Inventories()
			if invs[0].Revision != 0 || invs[0].Versions["amc"] != "v-test" || string(invs[0].Services) != `{"schema":1,"services":[]}` ||
				invs[1].Revision != 1 {
				t.Errorf("inventories: %+v", invs)
			}
			time.Sleep(600 * time.Millisecond)
			if i, _ := cp.Inventories(); len(i) != 2 {
				t.Errorf("an unchanged inventory was sent again: %d", len(i))
			}
		}
		cancel()
		srv.Close()
		<-done
	}
}

// v0.14.0: the FIRST 401 is retried quickly (a proxy re-sent the open long poll with the same nonce after a
// control-plane restart); before, the agent waited its whole backoff (up to 5 min).
func TestFirst401RetriedQuickly(t *testing.T) {
	cp := agenttest.New()
	cp.Poll = 300 * time.Millisecond
	srv := httptest.NewServer(cp)
	defer srv.Close()
	pre := setupPrefix(t, cp.PublicKey(), srv.URL+"/agent/")
	if err := agent.Enrol(context.Background(), pre, "app-1", agenttest.Token, os.Getuid(), os.Getgid(), nil); err != nil {
		t.Fatal(err)
	}
	cp.Refuse401(1)
	cp.Publish("app-1", 0, generate.Probes{TCP: []generate.TCPProbe{{Name: "link_web_db", Host: "db.example.com", Port: 5432}}}, 0, false, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		// a long MaxBackoff: if the agent backed off after the first 401 the status would not arrive in time
		_ = agent.Run(ctx, agent.Config{Prefix: pre, Host: "app-1", Run: (&fakeRun2{}).run,
			NotEnrolledWait: 50 * time.Millisecond, MaxBackoff: time.Hour, UnauthRetry: 100 * time.Millisecond})
		close(done)
	}()
	for i := 0; i < 150 && len(cp.Statuses()) == 0; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if s := cp.Statuses(); len(s) == 0 || s[0].Result != "applied" {
		t.Fatalf("after one 401 the list should be applied within ~3 s: %+v", s)
	}
	cancel()
	<-done
}
