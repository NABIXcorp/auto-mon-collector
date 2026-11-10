package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
)

const siteOn = "  site:\n    allow: true\n"

var noise = map[string]any{"cp-noise.yaml": "processors:\n  filter/noise:\n    error_mode: ignore\n"}

// siteRun runs root's half for a site request; update = what `monitoring-agent update` answers. It returns the
// result and the file names staged in --site-dir.
func (e *env) siteRun(out string, update error) (agent.UpdateResult, []string) {
	e.t.Helper()
	var staged []string
	res := Run(context.Background(), Options{
		Prefix: e.prefix, Host: "app-1.example.com", Running: "v0.23.0", Arch: "amd64", RootUID: os.Getuid(),
		Now: func() time.Time { return time.Unix(testNow, 0) }, Out: &e.out,
		Run: func(lock *os.File, name string, args ...string) ([]byte, error) {
			e.calls = append(e.calls, filepath.Base(name)+" "+strings.Join(args, " "))
			if len(args) == 5 && args[0] == "update" && args[3] == "--site-dir" {
				e.lockSeen = lock != nil
				ents, _ := os.ReadDir(args[4])
				for _, x := range ents {
					staged = append(staged, x.Name())
				}
				sort.Strings(staged)
				return []byte(out), update
			}
			return nil, errors.New("unexpected command " + name)
		},
	})
	return res, staged
}

func (e *env) siteResult() agent.SiteResult {
	e.t.Helper()
	var r agent.SiteResult
	if err := json.Unmarshal([]byte(e.read(agent.SiteResultFile)), &r); err != nil {
		e.t.Fatalf("%s: %v", agent.SiteResultFile, err)
	}
	return r
}

func siteDoc(rev int, files map[string]any) func(map[string]any) {
	return func(d map[string]any) {
		delete(d, "update")
		d["site"] = map[string]any{"revision": rev, "files": files}
	}
}

func TestSiteOK(t *testing.T) {
	e := newEnv(t, siteOn)
	if err := os.MkdirAll(filepath.Join(e.prefix, "config", "site.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.write("config/site.d/10-own.yaml", "processors: {}\n", 0o644)
	e.write("config/site.d/cp-old.yaml", "processors: {}\n", 0o644)
	e.request(siteDoc(5, noise), nil)
	res, staged := e.siteRun("update: done\n", nil)
	if res.Result != "ok" || !e.lockSeen {
		t.Fatalf("result %+v lock %v\n%s", res, e.lockSeen, e.out.String())
	}
	if strings.Join(staged, ",") != "10-own.yaml,cp-noise.yaml" {
		t.Errorf("staged site.d: %v (the host's own file kept, the old control-plane file replaced)", staged)
	}
	if r := e.siteResult(); r.Revision != 5 || r.DocRevision != 7 || r.Result != "ok" {
		t.Errorf("site result: %+v", r)
	}
	var rec record
	if err := unmarshal([]byte(e.read(RecordFile)), &rec); err != nil || rec.SiteRevision != 5 || rec.Revision != 7 {
		t.Errorf("record: %+v %v", rec, err)
	}
	if e.read(agent.UpdateResultFile) != "" {
		t.Error("a site job wrote the update result")
	}
	if ents, _ := filepath.Glob(filepath.Join(e.prefix, ".site-stage-*")); len(ents) != 0 {
		t.Errorf("stage dir left: %v", ents)
	}
	// the same request again: the revision is not newer, nothing runs again
	n := len(e.calls)
	if res, _ := e.siteRun("", nil); res.Result != "refused" || len(e.calls) != n {
		t.Errorf("replay: %+v %q", res, e.calls)
	}
	if r := e.siteResult(); r.Result != "ok" {
		t.Errorf("a replay changed the site result: %+v", r)
	}
}

func TestSiteRefusedAndRolledBack(t *testing.T) {
	cases := []struct {
		name, policy string
		files        map[string]any
		out          string
		err          error
		want, detail string
	}{
		{"switch off", "", noise, "", nil, "refused", "agent.site.allow"},
		{"outside the catalog (root does not trust the agent)", siteOn, map[string]any{"cp-x.yaml": "exporters:\n  debug: {}\n"}, "", nil, "refused", "not allowed"},
		{"plan fails", siteOn, noise, "update: the plan has failures: nothing was changed.\n", errors.New("exit 3"), "failed", "nothing changed"},
		{"start fails", siteOn, noise, "\nROLLED BACK: 1 failure(s), 0 warning(s). The new configuration is NOT active.\n", errors.New("exit 3"), "rolled_back", "previous one runs again"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, c.policy)
			e.request(siteDoc(2, c.files), nil)
			res, _ := e.siteRun(c.out, c.err)
			r := e.siteResult()
			if res.Result != c.want || r.Result != c.want || r.Revision != 2 || !strings.Contains(r.Detail, c.detail) {
				t.Fatalf("result %+v / %+v\n%s", res, r, e.out.String())
			}
			if c.want == "refused" && len(e.calls) != 0 {
				t.Errorf("a refused set ran %q", e.calls)
			}
		})
	}
}

// a new update and a set in one document: root does the update (the agent hands the set with a later document)
func TestSiteWaitsForAnUpdate(t *testing.T) {
	e := newEnv(t, "  update:\n    allow: true\n"+siteOn)
	e.request(func(d map[string]any) { d["site"] = map[string]any{"revision": 1, "files": noise} }, nil)
	if res := e.run(); res.Result != "ok" || res.ID != "u-0123456789" {
		t.Fatalf("the update first: %+v\n%s", res, e.out.String())
	}
	if e.read(agent.SiteResultFile) != "" {
		t.Error("the set ran together with the update")
	}
}
