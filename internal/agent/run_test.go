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
