package selfupdate

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

const servicesOn = "  services_edit:\n    allow: true\n"

func servicesDoc(rev int, set map[string]any) func(map[string]any) {
	return func(d map[string]any) {
		delete(d, "update")
		d["services"] = map[string]any{"revision": rev, "set": set}
	}
}

var redis6380 = map[string]any{"redis": map[string]any{"on": true, "port": 6380}}

// servicesRun runs root's half for a services request; update = what `monitoring-agent update` answers; check = the
// service check (nil = every kind answers); seen = the set file as `update` found it ("" = none).
func (e *env) servicesRun(out string, update error, check func(string, generate.ServiceSwitch) error) (res agent.UpdateResult, seen string, checked []string) {
	e.t.Helper()
	res = Run(context.Background(), Options{
		Prefix: e.prefix, Host: "app-1.example.com", Running: "v0.33.0", Arch: "amd64", RootUID: os.Getuid(),
		Now: func() time.Time { return time.Unix(testNow, 0) }, Out: &e.out,
		CheckService: func(_ context.Context, kind string, sw generate.ServiceSwitch) error {
			checked = append(checked, fmt.Sprintf("%s:%d%s", kind, sw.Port, sw.StatusPath))
			if check != nil {
				return check(kind, sw)
			}
			return nil
		},
		Run: func(lock *os.File, name string, args ...string) ([]byte, error) {
			e.calls = append(e.calls, filepath.Base(name)+" "+strings.Join(args, " "))
			if len(args) == 4 && args[0] == "update" && args[3] == "--no-fetch" {
				e.lockSeen = lock != nil
				seen = e.read(generate.ServicesFile)
				return []byte(out), update
			}
			return nil, errors.New("unexpected command " + name)
		},
	})
	return res, seen, checked
}

func (e *env) servicesResult() agent.ServicesResult {
	e.t.Helper()
	var r agent.ServicesResult
	if err := json.Unmarshal([]byte(e.read(agent.ServicesResultFile)), &r); err != nil {
		e.t.Fatalf("%s: %v", agent.ServicesResultFile, err)
	}
	return r
}

func TestServicesApplied(t *testing.T) {
	e := newEnv(t, servicesOn)
	if err := os.MkdirAll(filepath.Join(e.prefix, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	set := map[string]any{"redis": map[string]any{"on": true, "port": 6380}, "nginx": map[string]any{"on": true, "port": 8080}}
	e.request(servicesDoc(5, set), nil)
	res, seen, checked := e.servicesRun("update: done\n", nil, nil)
	if res.Result != "applied" || !e.lockSeen {
		t.Fatalf("result %+v lock %v\n%s", res, e.lockSeen, e.out.String())
	}
	if strings.Join(checked, ",") != "nginx:8080/nginx_status,redis:6380" {
		t.Errorf("checks: %q", checked)
	}
	ov, err := generate.LoadServicesOverlay(filepath.Join(e.prefix, filepath.FromSlash(generate.ServicesFile)))
	if err != nil || ov.Revision != 5 || ov.Set.String() != "nginx on :8080 /nginx_status, redis on :6380" {
		t.Errorf("set file: %v %+v", err, ov)
	}
	if !strings.Contains(seen, "revision 5") {
		t.Errorf("`update` ran before the set was written: %q", seen)
	}
	if fi, err := os.Stat(filepath.Join(e.prefix, filepath.FromSlash(generate.ServicesFile))); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm() != 0o644 {
		t.Errorf("set file mode %v", fi.Mode())
	}
	if r := e.servicesResult(); r.Revision != 5 || r.DocRevision != 7 || r.Result != "applied" {
		t.Errorf("services result: %+v", r)
	}
	var rec record
	if err := unmarshal([]byte(e.read(RecordFile)), &rec); err != nil || rec.ServicesRevision != 5 || rec.Revision != 7 {
		t.Errorf("record: %+v %v", rec, err)
	}
	if e.read(agent.UpdateResultFile) != "" || e.read(agent.AllowResultFile) != "" {
		t.Error("a services job wrote the update / allow result")
	}
	// the same request again: the revision is not newer, nothing runs again
	n := len(e.calls)
	if res, _, _ := e.servicesRun("", nil, nil); res.Result != "refused" || len(e.calls) != n {
		t.Errorf("replay: %+v %q", res, e.calls)
	}
	if r := e.servicesResult(); r.Result != "applied" {
		t.Errorf("a replay changed the services result: %+v", r)
	}
	// a newer, empty set removes the file
	e.request(func(d map[string]any) { servicesDoc(6, map[string]any{})(d); d["revision"] = 8 }, nil)
	if res, seen, _ := e.servicesRun("update: done\n", nil, nil); res.Result != "applied" || seen != "" {
		t.Fatalf("empty set: %+v %q\n%s", res, seen, e.out.String())
	}
	if _, err := os.Stat(filepath.Join(e.prefix, filepath.FromSlash(generate.ServicesFile))); !os.IsNotExist(err) {
		t.Errorf("empty set left the file: %v", err)
	}
	// the record keeps the last services revision root handled
	if err := unmarshal([]byte(e.read(RecordFile)), &rec); err != nil || rec.ServicesRevision != 6 {
		t.Errorf("record: %+v", rec)
	}
}

func TestServicesRefusedAndRolledBack(t *testing.T) {
	const prev = "revision: 1\nset:\n  redis: {on: true, port: 6379}\n"
	nginxNo := func(kind string, sw generate.ServiceSwitch) error {
		return fmt.Errorf("nginx stub_status not answering at http://127.0.0.1:%d%s: add the location (see the console steps)", sw.Port, sw.StatusPath)
	}
	cases := []struct {
		name, policy string
		set          map[string]any
		check        func(string, generate.ServiceSwitch) error
		out          string
		err          error
		want, detail string
	}{
		{"switch off", "", redis6380, nil, "", nil, "refused", "agent.services_edit.allow"},
		{"kind not in the list (root does not trust the agent)", servicesOn, map[string]any{"docker": map[string]any{"on": true, "port": 2375}}, nil, "", nil, "refused", `kind "docker"`},
		{"bad path", servicesOn, map[string]any{"nginx": map[string]any{"on": true, "port": 80, "status_path": "/../x?"}}, nil, "", nil, "refused", "status_path"},
		{"locked", servicesOn + "services:\n  redis:\n    enabled: false\n    locked: true\n", redis6380, nil, "", nil, "refused", "locked"},
		{"nginx not answering", servicesOn, map[string]any{"nginx": map[string]any{"on": true, "port": 80}}, nginxNo, "", nil, "refused", "stub_status not answering at http://127.0.0.1:80/nginx_status"},
		{"redis needs a password", servicesOn, redis6380, func(string, generate.ServiceSwitch) error {
			return errors.New("Redis needs a password: put it in Secrets (REDIS_PASSWORD)")
		}, "", nil, "refused", "Redis needs a password"},
		{"plan fails", servicesOn, redis6380, nil, "update: the plan has failures: nothing was changed.\n", errors.New("exit 3"), "failed", "nothing changed"},
		{"start fails", servicesOn, redis6380, nil, "\nROLLED BACK: 1 failure(s), 0 warning(s). The new configuration is NOT active.\n", errors.New("exit 3"), "rolled_back", "previous services"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, c.policy)
			if err := os.MkdirAll(filepath.Join(e.prefix, "config"), 0o755); err != nil {
				t.Fatal(err)
			}
			e.write(generate.ServicesFile, prev, 0o644)
			e.request(servicesDoc(2, c.set), nil)
			res, _, _ := e.servicesRun(c.out, c.err, c.check)
			r := e.servicesResult()
			if res.Result != c.want || r.Result != c.want || r.Revision != 2 || !strings.Contains(r.Detail, c.detail) {
				t.Fatalf("result %+v / %+v\n%s", res, r, e.out.String())
			}
			if c.want == "refused" && len(e.calls) != 0 {
				t.Errorf("a refused set ran %q", e.calls)
			}
			if got := e.read(generate.ServicesFile); got != prev {
				t.Errorf("the previous set is not back: %q", got)
			}
		})
	}
}

// a kind already on in the answers is not checked (the set changes nothing for it)
func TestServicesNoCheckForAKindOnInTheAnswers(t *testing.T) {
	e := newEnv(t, servicesOn+"services:\n  redis:\n    enabled: true\n")
	if err := os.MkdirAll(filepath.Join(e.prefix, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.request(servicesDoc(1, redis6380), nil)
	res, _, checked := e.servicesRun("update: done\n", nil, func(string, generate.ServiceSwitch) error { return errors.New("down") })
	if res.Result != "applied" || len(checked) != 0 {
		t.Fatalf("%+v %q\n%s", res, checked, e.out.String())
	}
}

// an allowlist overlay and a set in one document: root does the allowlist (the set waits)
func TestServicesWaitForAnAllowJob(t *testing.T) {
	e := newEnv(t, allowOn+servicesOn)
	if err := os.MkdirAll(filepath.Join(e.prefix, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.request(func(d map[string]any) {
		servicesDoc(1, redis6380)(d)
		d["allow"] = map[string]any{"revision": 1, "allow": allowSet([]any{5432}, false)}
	}, nil)
	res, _ := e.allowRun("update: done\n", nil)
	if res.Result != "ok" || e.read(agent.AllowResultFile) == "" {
		t.Fatalf("the allowlist first: %+v\n%s", res, e.out.String())
	}
	if e.read(agent.ServicesResultFile) != "" || e.read(generate.ServicesFile) != "" {
		t.Error("the services job ran together with the allowlist")
	}
	// the next document (same content, newer revision): now the set
	e.request(func(d map[string]any) {
		servicesDoc(1, redis6380)(d)
		d["allow"] = map[string]any{"revision": 1, "allow": allowSet([]any{5432}, false)}
		d["revision"] = 8
	}, nil)
	if res, _, _ := e.servicesRun("update: done\n", nil, nil); res.Result != "applied" {
		t.Fatalf("then the set: %+v\n%s", res, e.out.String())
	}
	var rec record
	if err := unmarshal([]byte(e.read(RecordFile)), &rec); err != nil || rec.AllowRevision != 1 || rec.ServicesRevision != 1 {
		t.Errorf("record: %+v %v", rec, err)
	}
}

// the real checks against local fakes
func TestCheckNginxAndRedis(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nginx_status" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "Active connections: 1 \nserver accepts handled requests\n 1 1 1 \nReading: 0 Writing: 1 Waiting: 0 \n")
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	if err := CheckNginx(ctx, addr, "/nginx_status"); err != nil {
		t.Errorf("stub_status: %v", err)
	}
	if err := CheckNginx(ctx, addr, "/other"); err == nil || !strings.Contains(err.Error(), "add the location") {
		t.Errorf("404: %v", err)
	}

	redis := func(answer string) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_, _ = bufio.NewReader(c).ReadString('\n')
				fmt.Fprint(c, answer)
				c.Close()
			}
		}()
		return ln.Addr().String()
	}
	no, yes := func() bool { return false }, func() bool { return true }
	if err := CheckRedis(ctx, redis("+PONG\r\n"), no); err != nil {
		t.Errorf("PONG: %v", err)
	}
	auth := redis("-NOAUTH Authentication required.\r\n")
	if err := CheckRedis(ctx, auth, no); err == nil || !strings.Contains(err.Error(), "Redis needs a password: put it in Secrets") {
		t.Errorf("NOAUTH without a password: %v", err)
	}
	if err := CheckRedis(ctx, auth, yes); err != nil {
		t.Errorf("NOAUTH with a password: %v", err)
	}
	if err := CheckRedis(ctx, redis("HTTP/1.1 400 Bad Request\r\n"), no); err == nil || !strings.Contains(err.Error(), "not a Redis answer") {
		t.Errorf("not Redis: %v", err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	if err := CheckRedis(ctx, closed, no); err == nil || !strings.Contains(err.Error(), "Redis not answering") {
		t.Errorf("closed port: %v", err)
	}
}

// hasSecret reads only whether the key is set
func TestHasSecret(t *testing.T) {
	e := newEnv(t, "")
	if (&Options{Prefix: e.prefix}).hasSecret("REDIS_PASSWORD") {
		t.Error("no secrets file")
	}
	if err := os.MkdirAll(filepath.Join(e.prefix, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	e.write("secrets/collector.env", "OO_TOKEN=x\nREDIS_PASSWORD=\n", 0o600)
	if (&Options{Prefix: e.prefix}).hasSecret("REDIS_PASSWORD") {
		t.Error("empty value counts")
	}
	e.write("secrets/collector.env", "OO_TOKEN=x\nREDIS_PASSWORD=pw\n", 0o600)
	if !(&Options{Prefix: e.prefix}).hasSecret("REDIS_PASSWORD") {
		t.Error("set value not seen")
	}
}
