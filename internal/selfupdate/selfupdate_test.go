package selfupdate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
)

const (
	oldBin  = "OLD AGENT v0.16.0"
	newBin  = "NEW AGENT v0.16.1"
	testNow = 1792700000
)

// env: an installed prefix (answers with an agent section, bin/monitoring-agent), a fake release server with a throwaway
// release key, a control-plane key that signs requests, and a fake runner.
type env struct {
	t        *testing.T
	prefix   string
	cp       ed25519.PrivateKey
	srv      *httptest.Server
	requests atomic.Int64
	files    map[string][]byte // served below /<version>/
	calls    []string
	lockSeen bool
	version  func(bin []byte) string // output of `bin/monitoring-agent version`
	update   error                   // result of `bin/monitoring-agent update`
	out      bytes.Buffer
	httpc    *http.Client // nil = default (the mirror tests: a TLS test server's client)
}

func newEnv(t *testing.T, policy string) *env {
	t.Helper()
	e := &env{t: t, prefix: t.TempDir()}
	_, e.cp, _ = ed25519.GenerateKey(rand.Reader)
	for _, d := range []string{"bin", "agent"} {
		if err := os.MkdirAll(filepath.Join(e.prefix, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ans := "agent:\n  url: https://agent.example.com/agent/\n  control_plane_key: \"" +
		agent.EncodeKey(e.cp.Public().(ed25519.PublicKey)) + "\"\n" + policy
	e.write("answers.yaml", ans, 0o644)
	e.write("bin/monitoring-agent", oldBin, 0o755)

	k, pub := testKey(t, elliptic.P256())
	bin := []byte(newBin)
	sums := sumsFor(map[string][]byte{"monitoring-agent-linux-amd64": bin, "monitoring-agent-linux-arm64": []byte("ARM"), "get.sh": []byte("sh")})
	e.files = map[string][]byte{"monitoring-agent-linux-amd64": bin, "SHA256SUMS": sums, "SHA256SUMS.sig": signSums(t, k, sums)}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.requests.Add(1)
		if !strings.HasPrefix(r.URL.Path, "/v0.16.1/") {
			http.NotFound(w, r)
			return
		}
		b, ok := e.files[strings.TrimPrefix(r.URL.Path, "/v0.16.1/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(e.srv.Close)
	oldBase, oldKey := baseURL, releaseKey
	baseURL, releaseKey = e.srv.URL+"/", pub
	t.Cleanup(func() { baseURL, releaseKey = oldBase, oldKey })
	e.version = func(b []byte) string {
		if string(b) == newBin {
			return "auto-mon-collector v0.16.1 (commit abc1234, built 2026-11-02T00:00:00Z, linux/amd64)\n"
		}
		return "auto-mon-collector v0.16.0 (commit 0000000, built 2026-10-23T00:00:00Z, linux/amd64)\n"
	}
	return e
}

func (e *env) write(rel, s string, mode os.FileMode) {
	e.t.Helper()
	p := filepath.Join(e.prefix, filepath.FromSlash(rel))
	if err := os.WriteFile(p, []byte(s), mode); err != nil {
		e.t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // umask
		e.t.Fatal(err)
	}
}

func (e *env) read(rel string) string {
	b, _ := os.ReadFile(filepath.Join(e.prefix, filepath.FromSlash(rel)))
	return string(b)
}

// request writes a signed request; change edits the document before signing, after edits it after signing.
func (e *env) request(change func(map[string]any), after func(map[string]any)) {
	e.t.Helper()
	doc := map[string]any{"host": "app-1.example.com", "revision": 7, "issued_at": testNow - 60, "expires_at": testNow + 3600,
		"probes": map[string]any{}, "update": map[string]any{"version": "v0.16.1", "id": "u-0123456789"}}
	if change != nil {
		change(doc)
	}
	b, _ := json.Marshal(doc)
	c, err := agent.CanonicalJSON(b)
	if err != nil {
		e.t.Fatal(err)
	}
	doc["sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(e.cp, c))
	if after != nil {
		after(doc)
	}
	raw, _ := json.Marshal(doc)
	e.write(agent.UpdateRequestFile, string(raw), 0o600)
}

func (e *env) run() agent.UpdateResult {
	e.t.Helper()
	return Run(context.Background(), Options{
		Prefix: e.prefix, Host: "app-1.example.com", Running: "v0.16.0", Arch: "amd64", RootUID: os.Getuid(),
		Now: func() time.Time { return time.Unix(testNow, 0) }, Out: &e.out, HTTP: e.httpc,
		Run: func(lock *os.File, name string, args ...string) ([]byte, error) {
			e.calls = append(e.calls, filepath.Base(name)+" "+strings.Join(args, " "))
			switch {
			case name == "systemctl":
				return nil, nil
			case len(args) > 0 && args[0] == "version":
				b, _ := os.ReadFile(name)
				return []byte(e.version(b)), nil
			case len(args) > 0 && args[0] == "update":
				e.lockSeen = lock != nil
				return []byte("update: done\n"), e.update
			}
			return nil, errors.New("unexpected command " + name)
		},
	})
}

func (e *env) result() agent.UpdateResult {
	e.t.Helper()
	r, err := agent.LoadUpdateResult(e.prefix)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func TestSelfUpdateOK(t *testing.T) {
	e := newEnv(t, "  update:\n    allow: true\n")
	e.request(nil, nil)
	res := e.run()
	if res.Result != "ok" || res.ID != "u-0123456789" || res.From != "v0.16.0" || res.To != "v0.16.1" {
		t.Fatalf("result: %+v\n%s", res, e.out.String())
	}
	if e.read("bin/monitoring-agent") != newBin || e.read("bin/monitoring-agent.before-v0.16.0") != oldBin {
		t.Errorf("binaries: agent=%q before=%q", e.read("bin/monitoring-agent"), e.read("bin/monitoring-agent.before-v0.16.0"))
	}
	want := []string{"monitoring-agent version", "monitoring-agent update --prefix " + e.prefix, "systemctl try-restart monitoring-agent.service"}
	if strings.Join(e.calls, "|") != strings.Join(want, "|") {
		t.Errorf("calls: %q", e.calls)
	}
	if !e.lockSeen {
		t.Error("the lock was not handed to `monitoring-agent update`")
	}
	if r := e.result(); r.Result != "ok" || r.ID != res.ID || r.At != testNow {
		t.Errorf("result file: %+v", r)
	}
	if !strings.Contains(e.read(RecordFile), `"u-0123456789"`) {
		t.Errorf("record: %s", e.read(RecordFile))
	}
	// the same request again (agent restarted it, or a replay): refused, the reported result stays
	e.calls = nil
	if res := e.run(); res.Result != "refused" || !strings.Contains(res.Detail, "not newer than the applied 7") {
		t.Errorf("repeat: %+v", res)
	}
	// the same id in a newer revision (the control plane repeats it until it has the result)
	e.request(func(d map[string]any) { d["revision"] = 8 }, nil)
	if res := e.run(); res.Result != "refused" || !strings.Contains(res.Detail, "handled already") {
		t.Errorf("same id, newer revision: %+v", res)
	}
	if r := e.result(); r.Result != "ok" {
		t.Errorf("a repeated request overwrote the result: %+v", r)
	}
	if len(e.calls) != 0 {
		t.Errorf("repeat ran %q", e.calls)
	}
}

func TestSelfUpdateRefused(t *testing.T) {
	_, otherCP, _ := ed25519.GenerateKey(rand.Reader)
	allow := "  update:\n    allow: true\n"
	cases := []struct {
		name, policy  string
		change, after func(map[string]any)
		want          string
	}{
		{"allow off (default)", "", nil, nil, "remote update is off"},
		{"allow false", "  update:\n    allow: false\n", nil, nil, "remote update is off"},
		{"same version", allow, func(d map[string]any) { d["update"] = map[string]any{"version": "v0.16.0", "id": "u-0123456789"} }, nil, "not newer"},
		{"downgrade", allow, func(d map[string]any) { d["update"] = map[string]any{"version": "v0.15.0", "id": "u-0123456789"} }, nil, "not newer"},
		{"outside the window", "  update:\n    allow: true\n    window: \"" + windowWithout(time.Unix(testNow, 0)) + "\"\n", nil, nil, "outside the update window"},
		{"wrong host", allow, func(d map[string]any) { d["host"] = "other.example.com" }, nil, "is for host"},
		{"expired", allow, func(d map[string]any) { d["expires_at"] = testNow - 1 }, nil, "expired"},
		{"no update", allow, func(d map[string]any) { delete(d, "update") }, nil, "asks for no update"},
		{"bad version", allow, func(d map[string]any) { d["update"] = map[string]any{"version": "v0.16.1/../x", "id": "u-0123456789"} }, nil, "release tag"},
		{"bad id", allow, func(d map[string]any) { d["update"] = map[string]any{"version": "v0.16.1", "id": "../x"} }, nil, "id malformed"},
		{"extra field", allow, func(d map[string]any) {
			d["update"] = map[string]any{"version": "v0.16.1", "id": "u-0123456789", "url": "https://evil.example.net/"}
		}, nil, "unknown field"},
		{"tampered after signing", allow, nil, func(d map[string]any) { d["update"] = map[string]any{"version": "v0.17.0", "id": "u-0123456789"} }, "bad signature"},
		{"signed by another key", allow, nil, func(d map[string]any) {
			delete(d, "sig")
			b, _ := json.Marshal(d)
			c, _ := agent.CanonicalJSON(b)
			d["sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(otherCP, c))
		}, "bad signature"},
		{"no signature", allow, nil, func(d map[string]any) { delete(d, "sig") }, "signature missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, c.policy)
			e.request(c.change, c.after)
			res := e.run()
			if res.Result != "refused" || !strings.Contains(res.Detail, c.want) {
				t.Fatalf("got %+v, want refused with %q", res, c.want)
			}
			if e.read("bin/monitoring-agent") != oldBin || e.requests.Load() != 0 || len(e.calls) != 0 {
				t.Errorf("something happened: agent=%q requests=%d calls=%q", e.read("bin/monitoring-agent"), e.requests.Load(), e.calls)
			}
		})
	}
}

// windowWithout: a one-hour window that does not contain t (local time).
func windowWithout(t time.Time) string {
	h := (t.Hour() + 2) % 24
	return time.Date(2000, 1, 1, h, 0, 0, 0, time.Local).Format("15:04") + "-" +
		time.Date(2000, 1, 1, (h+1)%24, 0, 0, 0, time.Local).Format("15:04")
}

func TestSelfUpdateWindowInside(t *testing.T) {
	now := time.Unix(testNow, 0)
	from := now.Add(-time.Hour).Format("15:04")
	to := now.Add(time.Hour).Format("15:04")
	e := newEnv(t, "  update:\n    allow: true\n    window: \""+from+"-"+to+"\"\n")
	e.request(nil, nil)
	if res := e.run(); res.Result != "ok" {
		t.Fatalf("%+v", res)
	}
}

// Replay guard: root's own record (not the agent's state) refuses an older revision.
func TestSelfUpdateOldRevisionRefused(t *testing.T) {
	e := newEnv(t, "  update:\n    allow: true\n")
	e.write(RecordFile, `{"id":"u-older00000","revision":9,"at":1}`+"\n", 0o644)
	e.request(nil, nil) // revision 7
	if res := e.run(); res.Result != "refused" || !strings.Contains(res.Detail, "not newer than the applied 9") {
		t.Fatalf("%+v", res)
	}
}

func TestSelfUpdateDownloadFailures(t *testing.T) {
	cases := map[string]struct {
		edit func(e *env)
		want string
	}{
		"binary changed": {func(e *env) { e.files["monitoring-agent-linux-amd64"] = []byte("EVIL") }, "checksum mismatch"},
		"sums changed": {func(e *env) {
			e.files["SHA256SUMS"] = append([]byte{}, e.files["SHA256SUMS"]...)
			e.files["SHA256SUMS"][0] ^= 1
		}, "not signed"},
		"signed by another key": {func(e *env) {
			k, _ := testKey(e.t, elliptic.P256())
			e.files["SHA256SUMS.sig"] = signSums(e.t, k, e.files["SHA256SUMS"])
		}, "not signed"},
		"no signature":   {func(e *env) { delete(e.files, "SHA256SUMS.sig") }, "HTTP 404"},
		"no asset":       {func(e *env) { delete(e.files, "monitoring-agent-linux-amd64") }, "HTTP 404"},
		"binary too big": {func(e *env) { old := maxBinary; maxBinary = 4; e.t.Cleanup(func() { maxBinary = old }) }, "too large"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, "  update:\n    allow: true\n")
			c.edit(e)
			e.request(nil, nil)
			res := e.run()
			if res.Result != "failed" || !strings.Contains(res.Detail, c.want) || !strings.Contains(res.Detail, "nothing changed") {
				t.Fatalf("got %+v, want failed with %q", res, c.want)
			}
			if e.read("bin/monitoring-agent") != oldBin || len(e.calls) != 0 {
				t.Errorf("changed: agent=%q calls=%q", e.read("bin/monitoring-agent"), e.calls)
			}
			if r := e.result(); r.Result != "failed" {
				t.Errorf("result file: %+v", r)
			}
		})
	}
}

func TestSelfUpdateRestoresOldBinary(t *testing.T) {
	t.Run("new binary reports another version", func(t *testing.T) {
		e := newEnv(t, "  update:\n    allow: true\n")
		e.version = func([]byte) string { return "auto-mon-collector v0.16.10 (commit x)\n" } // a prefix of v0.16.1 must not pass
		e.request(nil, nil)
		res := e.run()
		if res.Result != "rolled_back" || !strings.Contains(res.Detail, "previous version v0.16.0 restored") {
			t.Fatalf("%+v", res)
		}
		if e.read("bin/monitoring-agent") != oldBin {
			t.Errorf("bin/monitoring-agent = %q", e.read("bin/monitoring-agent"))
		}
		for _, c := range e.calls {
			if strings.HasPrefix(c, "monitoring-agent update") {
				t.Errorf("monitoring-agent update ran after a failed version check")
			}
		}
	})
	t.Run("monitoring-agent update fails", func(t *testing.T) {
		e := newEnv(t, "  update:\n    allow: true\n")
		e.update = errors.New("exit status 1")
		e.request(nil, nil)
		res := e.run()
		if res.Result != "rolled_back" || !strings.Contains(res.Detail, "update failed") {
			t.Fatalf("%+v", res)
		}
		if e.read("bin/monitoring-agent") != oldBin || e.read("bin/monitoring-agent.before-v0.16.0") != oldBin {
			t.Errorf("bin/monitoring-agent = %q", e.read("bin/monitoring-agent"))
		}
		if e.calls[len(e.calls)-1] != "systemctl try-restart monitoring-agent.service" {
			t.Errorf("agent not restarted onto the restored binary: %q", e.calls)
		}
	})
}

// mirrorEnv: answers with release_mirror = a TLS server (https only) that serves the same signed files, or 503.
func mirrorEnv(t *testing.T, works bool) (*env, *atomic.Int64) {
	e := newEnv(t, "  update:\n    allow: true\n")
	var hits atomic.Int64
	m := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if !works {
			http.Error(w, "warming", http.StatusServiceUnavailable)
			return
		}
		b, ok := e.files[strings.TrimPrefix(r.URL.Path, "/dl/v0.16.1/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(m.Close)
	e.httpc = m.Client()
	ans, _ := os.ReadFile(filepath.Join(e.prefix, "answers.yaml"))
	e.write("answers.yaml", "release_mirror: "+m.URL+"/dl/\n"+string(ans), 0o644)
	return e, &hits
}

func TestSelfUpdateFromMirror(t *testing.T) {
	e, hits := mirrorEnv(t, true)
	e.request(nil, nil)
	if res := e.run(); res.Result != "ok" {
		t.Fatalf("result: %+v\n%s", res, e.out.String())
	}
	if hits.Load() != 3 || e.requests.Load() != 0 {
		t.Errorf("mirror %d requests, GitHub %d: want 3 and 0", hits.Load(), e.requests.Load())
	}
}

func TestSelfUpdateMirrorFallsBackToGitHub(t *testing.T) {
	e, hits := mirrorEnv(t, false)
	e.request(nil, nil)
	if res := e.run(); res.Result != "ok" {
		t.Fatalf("result: %+v\n%s", res, e.out.String())
	}
	if hits.Load() == 0 || e.requests.Load() != 3 || !strings.Contains(e.out.String(), "release mirror") {
		t.Errorf("mirror %d, GitHub %d, out %s", hits.Load(), e.requests.Load(), e.out.String())
	}
}
