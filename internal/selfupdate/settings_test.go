package selfupdate

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
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

// v0.36.0: settings with values: written to the file, the effective answers checked; a bad group refuses the set
func TestSettingsValues(t *testing.T) {
	const groups = "  settings:\n    allow: [checks, oracle, rescan]\n"
	values := func(rev, doc int, v map[string]any) func(map[string]any) {
		return func(d map[string]any) {
			settingsDoc(rev, map[string]bool{"rescan": true})(d)
			d["settings"].(map[string]any)["values"] = v
			d["revision"] = doc
		}
	}
	checks := map[string]any{"http": []any{map[string]any{"url": "https://app.example.com/health", "comment": "app"}}, "tcp": []any{}}
	e := newEnv(t, groups+"services:\n  oracle:\n    non_cdb: true\n")
	if err := os.MkdirAll(filepath.Join(e.prefix, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.request(values(5, 7, map[string]any{"checks": checks, "oracle": map[string]any{"service": "ORCL", "user": "otel_mon", "capacity": true, "capacity_pdbs": []any{}}}), nil)
	if res, seen := e.settingsRun("update: done\n", nil); res.Result != "applied" || !strings.Contains(seen, "https://app.example.com/health") || !strings.Contains(seen, "otel_mon") {
		t.Fatalf("applied: %+v %q\n%s", res, seen, e.out.String())
	}
	eff, err := generate.LoadEffectiveAnswers(e.prefix)
	if err != nil || len(eff.Checks.HTTP) != 1 || eff.Services["oracle"].User != "otel_mon" || !eff.Services["oracle"].NonCDB {
		t.Errorf("effective: %v %+v %+v", err, eff.Checks, eff.Services)
	}
	if strings.Contains(e.read("answers.yaml"), "otel_mon") {
		t.Error("answers.yaml was edited")
	}
	before := e.read(generate.SettingsFile)
	cases := []struct {
		name   string
		v      map[string]any
		detail string
	}{
		{"unknown group", map[string]any{"checks": checks, "postgres": map[string]any{}}, "postgres: unknown group"},
		{"not consented", map[string]any{"tomcat": map[string]any{"logs": []any{}, "time_zone": "UTC", "login_path": ""}}, "tomcat is not in answers.yaml agent.settings.allow"},
		{"effective answers not valid", map[string]any{"oracle": map[string]any{"service": "ORCL", "user": "C##MON", "capacity": false, "capacity_pdbs": []any{}}}, "non_cdb with a common user"},
		{"unknown field", map[string]any{"checks": map[string]any{"http": []any{}, "tcp": []any{}, "icmp": []any{}}}, `unknown field "icmp"`},
	}
	for i, c := range cases {
		e.calls = nil
		e.request(values(6+i, 8+i, c.v), nil)
		res, _ := e.settingsRun("update: done\n", nil)
		if r := e.settingsResult(); res.Result != "refused" || !strings.Contains(r.Detail, c.detail) || len(e.calls) != 0 {
			t.Errorf("%s: %+v %+v %q", c.name, res, r, e.calls)
		}
		if e.read(generate.SettingsFile) != before {
			t.Errorf("%s: the installed set changed", c.name)
		}
	}
	// a pinned group: the answers write checks
	p := newEnv(t, groups+"checks:\n  http:\n    - url: https://own.example.com/\n")
	if err := os.MkdirAll(filepath.Join(p.prefix, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	p.request(values(1, 7, map[string]any{"checks": checks}), nil)
	if res, _ := p.settingsRun("", nil); res.Result != "refused" || !strings.Contains(p.settingsResult().Detail, "checks is pinned") {
		t.Errorf("pinned: %+v %+v", res, p.settingsResult())
	}
}

// v0.37.0: sealed passwords: root opens a new one, writes collector.env (backup first), records only the id, runs
// the update with --restart; the same id is not opened again; a failed update puts collector.env back
func TestSettingsPasswords(t *testing.T) {
	const secret = "Pa55-w0rd!"
	e := newEnv(t, "  settings:\n    allow: [oracle_password, redis_password, rescan]\n")
	if err := os.MkdirAll(filepath.Join(e.prefix, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(e.prefix, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	const envBefore = "OO_AUTH='Basic abc'\nORACLE_MON_PASSWORD='old'\n"
	e.write("secrets/collector.env", envBefore, 0o600)
	pwDoc := func(rev, doc int, pw map[string]any) func(map[string]any) {
		return func(d map[string]any) {
			settingsDoc(rev, map[string]bool{})(d)
			d["settings"].(map[string]any)["passwords"] = pw
			d["revision"] = doc
		}
	}
	var envSeen string
	run := func(out string, fail error) (agent.UpdateResult, []string) {
		var calls []string
		res := Run(context.Background(), Options{
			Prefix: e.prefix, Host: "app-1.example.com", Running: "v0.37.0", Arch: "amd64", RootUID: os.Getuid(),
			Now: func() time.Time { return time.Unix(testNow, 0) }, Out: &e.out,
			Run: func(lock *os.File, name string, args ...string) ([]byte, error) {
				calls = append(calls, filepath.Base(name)+" "+strings.Join(args, " "))
				if len(args) > 0 && args[0] == "update" {
					envSeen = e.read("secrets/collector.env")
					return []byte(out), fail
				}
				return nil, nil
			},
		})
		return res, calls
	}
	// no key pair yet: refused, nothing written
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	early, _ := generate.Seal(other.PublicKey().Bytes(), "oracle_password", []byte(secret))
	e.request(pwDoc(1, 7, map[string]any{"oracle_password": map[string]any{"id": "pw-1", "sealed": early}}), nil)
	if res, calls := run("update: done\n", nil); res.Result != "refused" || !strings.Contains(e.settingsResult().Detail, "no settings key pair") || len(calls) != 0 {
		t.Fatalf("no key: %+v %q", e.settingsResult(), calls)
	}
	if _, err := generate.EnsureSealKey(e.prefix); err != nil {
		t.Fatal(err)
	}
	priv, _ := generate.LoadSealPriv(e.prefix)
	pub := priv.PublicKey().Bytes()
	// sealed to another key / for another slot: refused
	wrongSlot, _ := generate.Seal(pub, "redis_password", []byte(secret))
	for i, b := range []string{early, wrongSlot} {
		e.request(pwDoc(2+i, 8+i, map[string]any{"oracle_password": map[string]any{"id": "pw-1", "sealed": b}}), nil)
		if res, calls := run("update: done\n", nil); res.Result != "refused" || !strings.Contains(e.settingsResult().Detail, "cannot open") || len(calls) != 0 {
			t.Errorf("blob %d: %+v %q", i, e.settingsResult(), calls)
		}
	}
	if e.read("secrets/collector.env") != envBefore {
		t.Fatal("collector.env changed by a refused set")
	}
	// a good one
	good, _ := generate.Seal(pub, "oracle_password", []byte(secret))
	e.request(pwDoc(5, 11, map[string]any{"oracle_password": map[string]any{"id": "pw-1", "sealed": good}}), nil)
	res, calls := run("update: done\n", nil)
	if res.Result != "applied" || len(calls) != 1 || !strings.HasSuffix(calls[0], "--no-fetch --restart") {
		t.Fatalf("applied: %+v %q\n%s", res, calls, e.out.String())
	}
	if !strings.Contains(envSeen, "ORACLE_MON_PASSWORD='"+secret+"'") || !strings.Contains(envSeen, "OO_AUTH='Basic abc'") {
		t.Errorf("collector.env as `update` saw it: %q", envSeen)
	}
	if e.read(envBackup) != envBefore {
		t.Errorf("backup: %q", e.read(envBackup))
	}
	file := e.read(generate.SettingsFile)
	if !strings.Contains(file, "oracle_password: pw-1") || strings.Contains(file, good) || strings.Contains(file, secret) {
		t.Errorf("settings file: %q", file)
	}
	if st, _ := generate.LoadPasswordState(e.prefix); st["oracle_password"] != "set" || st["redis_password"] != "not set" {
		t.Errorf("state: %v", st)
	}
	if strings.Contains(e.out.String(), secret) || strings.Contains(e.read(agent.SettingsResultFile), secret) {
		t.Error("the value was printed")
	}
	// the same id again (even sealed to an old key): not opened, no --restart
	e.request(pwDoc(6, 12, map[string]any{"oracle_password": map[string]any{"id": "pw-1", "sealed": early}}), nil)
	if res, calls := run("update: done\n", nil); res.Result != "applied" || len(calls) != 1 || strings.Contains(calls[0], "--restart") {
		t.Errorf("same id: %+v %q", res, calls)
	}
	// a new one whose update fails: collector.env, the file and the units go back
	afterGood := e.read("secrets/collector.env")
	fileBefore := e.read(generate.SettingsFile)
	r2, _ := generate.Seal(pub, "redis_password", []byte("r3dis"))
	e.request(pwDoc(7, 13, map[string]any{"oracle_password": map[string]any{"id": "pw-1", "sealed": early},
		"redis_password": map[string]any{"id": "pw-2", "sealed": r2}}), nil)
	res, calls = run("\nROLLED BACK: 1 failure(s), 0 warning(s). The new configuration is NOT active.\n", errors.New("exit 3"))
	if res.Result != "rolled_back" || len(calls) != 2 || calls[1] != "systemctl try-restart monitoring-collector.service" {
		t.Fatalf("rolled back: %+v %q\n%s", res, calls, e.out.String())
	}
	if !strings.Contains(envSeen, "REDIS_PASSWORD='r3dis'") || e.read("secrets/collector.env") != afterGood || e.read(generate.SettingsFile) != fileBefore {
		t.Errorf("not restored: env %q file %q", e.read("secrets/collector.env"), e.read(generate.SettingsFile))
	}
}
