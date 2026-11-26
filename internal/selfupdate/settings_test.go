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

const settingsOn = "  settings:\n    allow: [disk_scan, rescan, docker, services_edit]\n"

func settingsDoc(rev int, set map[string]bool) func(map[string]any) {
	return func(d map[string]any) {
		delete(d, "update")
		d["settings"] = map[string]any{"revision": rev, "set": set}
	}
}

// settingsRun runs root's half for a request; update = what `monitoring-agent update` answers; seen = the set file
// as `update` found it ("" = none).
func (e *env) settingsRun(out string, update error) (res agent.UpdateResult, seen string) {
	e.t.Helper()
	res = Run(context.Background(), Options{
		Prefix: e.prefix, Host: "app-1.example.com", Running: "v0.35.0", Arch: "amd64", RootUID: os.Getuid(),
		Now: func() time.Time { return time.Unix(testNow, 0) }, Out: &e.out,
		Run: func(lock *os.File, name string, args ...string) ([]byte, error) {
			e.calls = append(e.calls, filepath.Base(name)+" "+strings.Join(args, " "))
			if len(args) == 4 && args[0] == "update" && args[3] == "--no-fetch" {
				e.lockSeen = lock != nil
				seen = e.read(generate.SettingsFile)
				return []byte(out), update
			}
			return nil, errors.New("unexpected command " + name)
		},
	})
	return res, seen
}

func (e *env) settingsResult() agent.SettingsResult {
	e.t.Helper()
	var r agent.SettingsResult
	if err := json.Unmarshal([]byte(e.read(agent.SettingsResultFile)), &r); err != nil {
		e.t.Fatalf("%s: %v", agent.SettingsResultFile, err)
	}
	return r
}

func TestSettingsApplied(t *testing.T) {
	e := newEnv(t, settingsOn)
	if err := os.MkdirAll(filepath.Join(e.prefix, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.request(settingsDoc(5, map[string]bool{"rescan": true, "docker": false}), nil)
	res, seen := e.settingsRun("update: done\n", nil)
	if res.Result != "applied" || !e.lockSeen {
		t.Fatalf("result %+v lock %v\n%s", res, e.lockSeen, e.out.String())
	}
	ov, err := generate.LoadSettingsOverlay(filepath.Join(e.prefix, filepath.FromSlash(generate.SettingsFile)))
	if err != nil || ov.Revision != 5 || ov.Set.String() != "docker off, rescan on" {
		t.Errorf("set file: %v %+v", err, ov)
	}
	if !strings.Contains(seen, "revision 5") {
		t.Errorf("`update` ran before the set was written: %q", seen)
	}
	if fi, err := os.Stat(filepath.Join(e.prefix, filepath.FromSlash(generate.SettingsFile))); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm() != 0o644 {
		t.Errorf("set file mode %v", fi.Mode())
	}
	if r := e.settingsResult(); r.Revision != 5 || r.DocRevision != 7 || r.Result != "applied" {
		t.Errorf("settings result: %+v", r)
	}
	var rec record
	if err := unmarshal([]byte(e.read(RecordFile)), &rec); err != nil || rec.SettingsRevision != 5 || rec.Revision != 7 {
		t.Errorf("record: %+v %v", rec, err)
	}
	if e.read(agent.UpdateResultFile) != "" || e.read(agent.ServicesResultFile) != "" {
		t.Error("a settings job wrote another job's result")
	}
	if strings.Contains(e.read("answers.yaml"), "rescan:") {
		t.Error("answers.yaml was edited")
	}
	// the same request again: not newer, nothing runs
	n := len(e.calls)
	if res, _ := e.settingsRun("", nil); res.Result != "refused" || len(e.calls) != n {
		t.Errorf("replay: %+v %q", res, e.calls)
	}
	// a newer, empty set removes the file
	e.request(func(d map[string]any) { settingsDoc(6, map[string]bool{})(d); d["revision"] = 8 }, nil)
	if res, seen := e.settingsRun("update: done\n", nil); res.Result != "applied" || seen != "" {
		t.Fatalf("empty set: %+v %q\n%s", res, seen, e.out.String())
	}
	if _, err := os.Stat(filepath.Join(e.prefix, filepath.FromSlash(generate.SettingsFile))); !os.IsNotExist(err) {
		t.Errorf("empty set left the file: %v", err)
	}
}

func TestSettingsRefusedAndRolledBack(t *testing.T) {
	const prev = "revision: 1\nset:\n  rescan: true\n"
	cases := []struct {
		name, policy string
		set          map[string]bool
		out          string
		err          error
		want, detail string
	}{
		{"no consent", "", map[string]bool{"rescan": true}, "", nil, "refused", "agent.settings.allow"},
		{"unknown key (root does not trust the agent)", settingsOn, map[string]bool{"rescan": true, "update": true}, "", nil, "refused", `unknown key "update"`},
		{"not in the consent list", settingsOn, map[string]bool{"allow_edit": true}, "", nil, "refused", "allow_edit is not in answers.yaml agent.settings.allow"},
		{"pinned in the answers", settingsOn + "  disk_scan:\n    allow: false\n", map[string]bool{"rescan": true, "disk_scan": true}, "", nil, "refused", "disk_scan is pinned"},
		{"plan fails", settingsOn, map[string]bool{"rescan": false}, "update: the plan has failures: nothing was changed.\n", errors.New("exit 3"), "failed", "nothing changed"},
		{"start fails", settingsOn, map[string]bool{"docker": true}, "\nROLLED BACK: 1 failure(s), 0 warning(s). The new configuration is NOT active.\n", errors.New("exit 3"), "rolled_back", "previous settings"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, c.policy)
			if err := os.MkdirAll(filepath.Join(e.prefix, "config"), 0o755); err != nil {
				t.Fatal(err)
			}
			e.write(generate.SettingsFile, prev, 0o644)
			e.request(settingsDoc(2, c.set), nil)
			res, _ := e.settingsRun(c.out, c.err)
			r := e.settingsResult()
			if res.Result != c.want || r.Result != c.want || r.Revision != 2 || !strings.Contains(r.Detail, c.detail) {
				t.Fatalf("result %+v / %+v\n%s", res, r, e.out.String())
			}
			if c.want == "refused" && len(e.calls) != 0 {
				t.Errorf("a refused set ran %q", e.calls)
			}
			if got := e.read(generate.SettingsFile); got != prev {
				t.Errorf("the previous set is not back: %q", got)
			}
		})
	}
}

// service switches and settings in one document: root does the service switches first (one root job per document)
func TestSettingsWaitForAServicesJob(t *testing.T) {
	e := newEnv(t, settingsOn+servicesOn)
	if err := os.MkdirAll(filepath.Join(e.prefix, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	both := func(rev int) func(map[string]any) {
		return func(d map[string]any) {
			settingsDoc(1, map[string]bool{"rescan": true})(d)
			d["services"] = map[string]any{"revision": 1, "set": redis6380}
			d["revision"] = rev
		}
	}
	e.request(both(7), nil)
	if res, _, _ := e.servicesRun("update: done\n", nil, nil); res.Result != "applied" {
		t.Fatalf("the services first: %+v\n%s", res, e.out.String())
	}
	if e.read(agent.SettingsResultFile) != "" || e.read(generate.SettingsFile) != "" {
		t.Error("the settings job ran together with the services job")
	}
	e.request(both(8), nil)
	if res, _ := e.settingsRun("update: done\n", nil); res.Result != "applied" {
		t.Fatalf("then the settings: %+v\n%s", res, e.out.String())
	}
	var rec record
	if err := unmarshal([]byte(e.read(RecordFile)), &rec); err != nil || rec.ServicesRevision != 1 || rec.SettingsRevision != 1 {
		t.Errorf("record: %+v %v", rec, err)
	}
}

// the console switched services_edit on (installed set): a services job is accepted (root reads the EFFECTIVE switch)
func TestServicesEditSwitchedOnBySettings(t *testing.T) {
	e := newEnv(t, settingsOn)
	if err := os.MkdirAll(filepath.Join(e.prefix, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.request(servicesDoc(1, redis6380), nil)
	if res, _, _ := e.servicesRun("update: done\n", nil, nil); res.Result != "refused" {
		t.Fatalf("without the setting: %+v", res)
	}
	e.write(generate.SettingsFile, "revision: 3\nset:\n  services_edit: true\n", 0o644)
	e.request(func(d map[string]any) { servicesDoc(2, redis6380)(d); d["revision"] = 8 }, nil)
	if res, _, _ := e.servicesRun("update: done\n", nil, nil); res.Result != "applied" {
		t.Fatalf("with the setting: %+v\n%s", res, e.out.String())
	}
}
