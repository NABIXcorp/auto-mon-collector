package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

const allowOn = "  allow_edit:\n    allow: true\n    ping: true\n    max_probes: 50\n"

func allowSet(ports []any, ping bool) map[string]any {
	return map[string]any{"domains": []any{"db.example.net"}, "networks": []any{"192.0.2.0/24"}, "ports": ports,
		"max_probes": 40, "min_interval_s": 0, "ping": ping}
}

var emptyAllow = map[string]any{"domains": []any{}, "networks": []any{}, "ports": []any{}, "max_probes": 0, "min_interval_s": 0, "ping": false}

func allowDoc(rev int, allow map[string]any) func(map[string]any) {
	return func(d map[string]any) {
		delete(d, "update")
		d["allow"] = map[string]any{"revision": rev, "allow": allow}
	}
}

// allowRun runs root's half for an allowlist request; update = what `monitoring-agent update` answers; seen = the
// overlay file as `update` found it ("" = none).
func (e *env) allowRun(out string, update error) (res agent.UpdateResult, seen string) {
	e.t.Helper()
	res = Run(context.Background(), Options{
		Prefix: e.prefix, Host: "app-1.example.com", Running: "v0.26.0", Arch: "amd64", RootUID: os.Getuid(),
		Now: func() time.Time { return time.Unix(testNow, 0) }, Out: &e.out,
		Run: func(lock *os.File, name string, args ...string) ([]byte, error) {
			e.calls = append(e.calls, filepath.Base(name)+" "+strings.Join(args, " "))
			if len(args) == 4 && args[0] == "update" && args[3] == "--no-fetch" {
				e.lockSeen = lock != nil
				seen = e.read(generate.AllowOverlayFile)
				return []byte(out), update
			}
			return nil, errors.New("unexpected command " + name)
		},
	})
	return res, seen
}

func (e *env) allowResult() agent.AllowResult {
	e.t.Helper()
	var r agent.AllowResult
	if err := json.Unmarshal([]byte(e.read(agent.AllowResultFile)), &r); err != nil {
		e.t.Fatalf("%s: %v", agent.AllowResultFile, err)
	}
	return r
}

func TestAllowOK(t *testing.T) {
	e := newEnv(t, allowOn)
	if err := os.MkdirAll(filepath.Join(e.prefix, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.request(allowDoc(5, allowSet([]any{5432, 22}, true)), nil)
	res, seen := e.allowRun("update: done\n", nil)
	if res.Result != "ok" || !e.lockSeen {
		t.Fatalf("result %+v lock %v\n%s", res, e.lockSeen, e.out.String())
	}
	ov, err := generate.LoadAllowOverlay(filepath.Join(e.prefix, filepath.FromSlash(generate.AllowOverlayFile)))
	if err != nil || ov.String() != "domains db.example.net; networks 192.0.2.0/24; ports 5432,22; max 40 probes; interval >= 0 s; ping true" {
		t.Errorf("overlay file: %v %s", err, ov)
	}
	if !strings.Contains(seen, "revision 5") {
		t.Errorf("`update` ran before the overlay was written: %q", seen)
	}
	if fi, err := os.Stat(filepath.Join(e.prefix, filepath.FromSlash(generate.AllowOverlayFile))); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm() != 0o644 {
		t.Errorf("overlay mode %v", fi.Mode())
	}
	if r := e.allowResult(); r.Revision != 5 || r.DocRevision != 7 || r.Result != "ok" {
		t.Errorf("allow result: %+v", r)
	}
	var rec record
	if err := unmarshal([]byte(e.read(RecordFile)), &rec); err != nil || rec.AllowRevision != 5 || rec.Revision != 7 {
		t.Errorf("record: %+v %v", rec, err)
	}
	if e.read(agent.UpdateResultFile) != "" || e.read(agent.SiteResultFile) != "" {
		t.Error("an allowlist job wrote the update / site result")
	}
	// the same request again: the revision is not newer, nothing runs again
	n := len(e.calls)
	if res, _ := e.allowRun("", nil); res.Result != "refused" || len(e.calls) != n {
		t.Errorf("replay: %+v %q", res, e.calls)
	}
	if r := e.allowResult(); r.Result != "ok" {
		t.Errorf("a replay changed the allow result: %+v", r)
	}
	// a newer, empty overlay removes the file
	e.request(func(d map[string]any) { allowDoc(6, emptyAllow)(d); d["revision"] = 8 }, nil)
	if res, seen := e.allowRun("update: done\n", nil); res.Result != "ok" || seen != "" {
		t.Fatalf("empty overlay: %+v %q\n%s", res, seen, e.out.String())
	}
	if _, err := os.Stat(filepath.Join(e.prefix, filepath.FromSlash(generate.AllowOverlayFile))); !os.IsNotExist(err) {
		t.Errorf("empty overlay left the file: %v", err)
	}
}

func TestAllowRefusedAndRolledBack(t *testing.T) {
	const prev = "ports: [8080]\n"
	cases := []struct {
		name, policy string
		allow        map[string]any
		out          string
		err          error
		want, detail string
	}{
		{"switch off", "", allowSet([]any{5432}, false), "", nil, "refused", "agent.allow_edit.allow"},
		{"ping not allowed (root does not trust the agent)", "  allow_edit:\n    allow: true\n    max_probes: 50\n", allowSet([]any{5432}, true), "", nil, "refused", "allow_edit.ping"},
		{"above the ceiling", allowOn, map[string]any{"domains": []any{}, "networks": []any{}, "ports": []any{}, "max_probes": 51, "min_interval_s": 0, "ping": false}, "", nil, "refused", "ceiling 50"},
		{"network too wide", allowOn, map[string]any{"domains": []any{}, "networks": []any{"::/0"}, "ports": []any{}, "max_probes": 0, "min_interval_s": 0, "ping": false}, "", nil, "refused", "/48"},
		{"plan fails", allowOn, allowSet([]any{5432}, false), "update: the plan has failures: nothing was changed.\n", errors.New("exit 3"), "failed", "nothing changed"},
		{"start fails", allowOn, allowSet([]any{5432}, true), "\nROLLED BACK: 1 failure(s), 0 warning(s). The new configuration is NOT active.\n", errors.New("exit 3"), "rolled_back", "previous allowlist"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, c.policy)
			if err := os.MkdirAll(filepath.Join(e.prefix, "config"), 0o755); err != nil {
				t.Fatal(err)
			}
			e.write(generate.AllowOverlayFile, prev, 0o644)
			e.request(allowDoc(2, c.allow), nil)
			res, _ := e.allowRun(c.out, c.err)
			r := e.allowResult()
			if res.Result != c.want || r.Result != c.want || r.Revision != 2 || !strings.Contains(r.Detail, c.detail) {
				t.Fatalf("result %+v / %+v\n%s", res, r, e.out.String())
			}
			if c.want == "refused" && len(e.calls) != 0 {
				t.Errorf("a refused overlay ran %q", e.calls)
			}
			if got := e.read(generate.AllowOverlayFile); got != prev {
				t.Errorf("the previous overlay is not back: %q", got)
			}
		})
	}
}

// a new overlay set and an allowlist overlay in one document: root does the set (the allowlist waits)
func TestAllowWaitsForASiteJob(t *testing.T) {
	e := newEnv(t, siteOn+allowOn)
	e.request(func(d map[string]any) {
		allowDoc(1, allowSet([]any{5432}, false))(d)
		d["site"] = map[string]any{"revision": 1, "files": noise}
	}, nil)
	res, _ := e.siteRun("update: done\n", nil)
	if res.Result != "ok" || e.read(agent.SiteResultFile) == "" {
		t.Fatalf("the set first: %+v\n%s", res, e.out.String())
	}
	if e.read(agent.AllowResultFile) != "" || e.read(generate.AllowOverlayFile) != "" {
		t.Error("the allowlist ran together with the set")
	}
}
