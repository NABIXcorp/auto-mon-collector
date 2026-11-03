package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/assets"
	"github.com/NABIXcorp/auto-mon-collector/internal/collector"
)

// fakeSource is the signed release in tests: the collector binary is "BIN".
type fakeSource struct{}

func (fakeSource) Sum(context.Context, string) ([32]byte, error) {
	return sha256.Sum256([]byte("BIN")), nil
}
func (fakeSource) Fetch(_ context.Context, _ string, _ [32]byte, dir string) (string, error) {
	p := filepath.Join(dir, collector.Name)
	return p, os.WriteFile(p, []byte("BIN"), 0o755)
}

// fakeRunner records commands and answers like a host where everything works.
type fakeRunner struct {
	cmds     []string
	selinux  bool
	semanage bool
	readable bool
	validate error
	envSeen  []string
	smokeOut string // collector output during the smoke run
	smokeEnv []string
	smokeErr error
	stopped  bool // the stop callback asked for an early stop
	inactive int  // the next N `systemctl is-active` calls report "not active"
	acl      bool // getfacl shows an entry for the collector user

	probeVersion string // output of cloudprober --version ("" = not installed)
	configtest   error  // cloudprober --configtest result
}

func (f *fakeRunner) Timed(_ context.Context, env []string, _ time.Duration, stop func(string) bool,
	name string, args ...string) ([]byte, error) {
	f.cmds = append(f.cmds, "TIMED "+filepath.Base(name)+" "+strings.Join(args, " "))
	f.smokeEnv = env
	var out []string
	for _, l := range strings.Split(f.smokeOut, "\n") {
		out = append(out, l)
		if stop(l) {
			f.stopped = true
			break
		}
	}
	return []byte(strings.Join(out, "\n")), f.smokeErr
}

func (f *fakeRunner) Run(name string, args ...string) error {
	c := name + " " + strings.Join(args, " ")
	f.cmds = append(f.cmds, c)
	switch {
	case name == "selinuxenabled" && !f.selinux:
		return os.ErrNotExist
	case name == "runuser" && !f.readable:
		return os.ErrPermission
	case name == "systemctl" && args[0] == "is-active" && f.inactive > 0:
		f.inactive--
		return os.ErrProcessDone
	}
	return nil
}

func (f *fakeRunner) Output(env []string, name string, args ...string) ([]byte, error) {
	f.cmds = append(f.cmds, "OUT "+filepath.Base(name)+" "+strings.Join(args, " "))
	switch {
	case filepath.Base(name) == "cloudprober" && len(args) == 1 && args[0] == "--version":
		return []byte(f.probeVersion + "\n"), nil
	case filepath.Base(name) == "cloudprober" && len(args) > 0 && args[0] == "--configtest":
		if f.configtest != nil {
			return []byte("Config test failed. Err: unknown field: protocol\n"), f.configtest
		}
		return nil, nil
	case name == "getfacl":
		if f.acl {
			return []byte("user::rw-\nuser:otelcol-contrib:r--\n"), nil
		}
		return []byte("user::rw-\n"), nil
	case len(args) > 0 && args[0] == "validate":
		f.envSeen = env
		if f.validate != nil {
			return []byte("Error: bad config, password was s3cr3tvalue\n"), f.validate
		}
		return nil, nil
	}
	return nil, nil
}

func (f *fakeRunner) LookPath(name string) bool { return name != "semanage" || f.semanage }

func (f *fakeRunner) has(sub string) bool {
	for _, c := range f.cmds {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

// needSymlinks: apply links the systemd units; Windows needs admin rights for symlinks. CI runs on Linux.
func needSymlinks(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs Linux (unit symlinks); runs in CI")
	}
}

type host struct {
	t    *testing.T
	root string
}

func newHost(t *testing.T) host {
	h := host{t, t.TempDir()}
	h.write("/etc/os-release", "PRETTY_NAME=\"Test Linux 9\"\n", 0o644)
	h.write("/etc/passwd", "root:x:0:0::/root:/bin/bash\notelcol-contrib:x:990:990::/opt/monitoring/data:/sbin/nologin\n", 0o644)
	h.write("/etc/group", "root:x:0:\ntomcat:x:992:\notelcol-contrib:x:990:\n", 0o644)
	h.write("/var/log/app/alert.log", "x\n", 0o640)
	return h
}

func (h host) write(p, s string, mode os.FileMode) {
	h.t.Helper()
	fp := filepath.Join(h.root, filepath.FromSlash(p))
	if err := os.MkdirAll(filepath.Dir(fp), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(fp, []byte(s), mode); err != nil {
		h.t.Fatal(err)
	}
}

func (h host) read(p string) string {
	b, _ := os.ReadFile(filepath.Join(h.root, filepath.FromSlash(p)))
	return string(b)
}

func desired() Desired {
	return Desired{
		HostYAML:   []byte("receivers: {}\n"),
		HostEnv:    []byte("ORACLE_MON=on\n"),
		Site:       map[string][]byte{"10-site.yaml": []byte("processors: {}\n")},
		SecretKeys: []string{"OO_ENDPOINT", "OO_AUTH", "ORACLE_MON_PASSWORD"},
		ReadFiles:  []string{"/var/log/app/alert.log"},
		Groups:     []string{"tomcat"},
		Version:    []byte("installer=amc test\ncollector=" + collector.Name + "\n"),
		Inventory:  []byte("{\"schema\": 1}\n"),
	}
}

func run(t *testing.T, h host, r *fakeRunner, apply, start, fetch bool) (Result, string) {
	return runSmoke(t, h, r, apply, start, fetch, false)
}

func runSmoke(t *testing.T, h host, r *fakeRunner, apply, start, fetch, smoke bool) (Result, string) {
	t.Helper()
	return runWith(t, h, r, apply, start, fetch, smoke, desired())
}

func runWith(t *testing.T, h host, r *fakeRunner, apply, start, fetch, smoke bool, d Desired) (Result, string) {
	t.Helper()
	var out bytes.Buffer
	res, err := Run(context.Background(), Options{
		Root: h.root, Apply: apply, Start: start, Fetch: fetch, Smoke: smoke, Rollback: true, Arch: "amd64",
		SkipRootCheck: true, RootUID: os.Getuid(), StartWait: time.Millisecond, Out: &out, Runner: r,
		Now:       func() time.Time { return time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) },
		Chown:     func(string, int, int) error { return nil },
		Collector: fakeSource{},
		ProbeFetcher: func(_ context.Context, _, dir string) (string, error) {
			p := filepath.Join(dir, "cloudprober")
			return p, os.WriteFile(p, []byte("PROBER"), 0o755)
		},
	}, d)
	if err != nil {
		t.Fatal(err)
	}
	return res, out.String()
}

func TestCheckModeChangesNothing(t *testing.T) {
	h := newHost(t)
	r := &fakeRunner{}
	res, out := run(t, h, r, false, false, true)
	if res.Applied {
		t.Error("check mode applied")
	}
	if _, err := os.Stat(filepath.Join(h.root, "opt")); err == nil {
		t.Errorf("check mode created files:\n%s", out)
	}
	for _, c := range r.cmds {
		if strings.HasPrefix(c, "useradd") || strings.HasPrefix(c, "setfacl") || strings.HasPrefix(c, "systemctl") {
			t.Errorf("check mode ran a changing command: %s", c)
		}
	}
	for _, want := range []string{"would: mkdir", "would: setfacl -m u:otelcol-contrib:r /var/log/app/alert.log",
		"would: usermod -aG tomcat otelcol-contrib", "FAIL  /opt/monitoring/secrets/collector.env missing",
		"NEW    config/host.yaml", "STOP: 1 failure(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestApplyStartAndIdempotent(t *testing.T) {
	needSymlinks(t)
	h := newHost(t)
	h.write("/opt/monitoring/secrets/collector.env",
		"OO_ENDPOINT='https://backend.example.com'\nOO_AUTH='Basic fake'\nORACLE_MON_PASSWORD='123456'\n", 0o600)
	r := &fakeRunner{readable: true}
	res, out := run(t, h, r, true, true, true)
	if res.Failures != 0 || !res.Applied {
		t.Fatalf("apply failed:\n%s", out)
	}
	if !strings.Contains(h.read("/opt/monitoring/systemd/monitoring-collector.service"),
		"--config=/opt/monitoring/config/site.d/10-site.yaml") {
		t.Error("site.d file not in ExecStart")
	}
	if got := h.read("/opt/monitoring/config/host.env"); got != "ORACLE_MON=on\n" {
		t.Errorf("host.env = %q", got)
	}
	if link, err := os.Readlink(filepath.Join(h.root, "etc/systemd/system/monitoring-collector.service")); err != nil ||
		link != "/opt/monitoring/systemd/monitoring-collector.service" {
		t.Errorf("unit link = %q, %v", link, err)
	}
	for _, c := range []string{"systemctl enable", "systemctl restart", "systemctl is-active -q monitoring-collector.service"} {
		if !r.has(c) {
			t.Errorf("missing command %q in %v", c, r.cmds)
		}
	}
	// validate got the secrets via the environment, never via arguments
	joined := strings.Join(r.envSeen, " ")
	if !strings.Contains(joined, "ORACLE_MON_PASSWORD=123456") || r.has("123456") {
		t.Errorf("secrets must reach validate only via env; env=%v", r.envSeen)
	}
	// second run: no file changes (the fake runner does not edit /etc/group, so "would: usermod" may remain)
	r2 := &fakeRunner{readable: true}
	_, out2 := run(t, h, r2, false, false, true)
	if strings.Contains(out2, "\n  CHANGE ") || strings.Contains(out2, "\n  NEW    ") ||
		!strings.Contains(out2, "CHECK done: 0 failures") {
		t.Errorf("second run is not clean:\n%s", out2)
	}
}

func TestBackupAndStaleSiteRemoved(t *testing.T) {
	needSymlinks(t)
	h := newHost(t)
	h.write("/opt/monitoring/secrets/collector.env", "OO_ENDPOINT=x\nOO_AUTH=y\nORACLE_MON_PASSWORD=z\n", 0o600)
	h.write("/opt/monitoring/config/config.yaml", "old\n", 0o644)
	h.write("/opt/monitoring/config/site.d/99-old.yaml", "old\n", 0o644)
	h.write("/opt/monitoring/bin/monitoring-collector", "BIN", 0o755) // fetch is off in this test
	r := &fakeRunner{readable: true}
	res, out := run(t, h, r, true, false, false)
	if res.Failures != 0 {
		t.Fatalf("%s", out)
	}
	if h.read("/opt/monitoring/backup/20261005-120000/config/config.yaml") != "old\n" {
		t.Errorf("backup missing:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(h.root, "opt/monitoring/config/site.d/99-old.yaml")); err == nil {
		t.Error("stale site.d file not removed")
	}
	if !strings.Contains(out, "CHANGE config/config.yaml") || !strings.Contains(out, "REMOVE config/site.d/99-old.yaml") {
		t.Errorf("diff report missing:\n%s", out)
	}
}

func TestValidateFailureStopsAndMasksSecrets(t *testing.T) {
	h := newHost(t)
	h.write("/opt/monitoring/secrets/collector.env", "OO_ENDPOINT=x\nOO_AUTH=y\nORACLE_MON_PASSWORD=s3cr3tvalue\n", 0o600)
	r := &fakeRunner{readable: true, validate: os.ErrInvalid}
	res, out := run(t, h, r, true, true, true)
	if res.Applied || res.Failures == 0 {
		t.Errorf("validate failure must stop before units / start:\n%s", out)
	}
	if strings.Contains(out, "s3cr3tvalue") || !strings.Contains(out, "password was ***") {
		t.Errorf("secret not masked:\n%s", out)
	}
	if r.has("systemctl restart") {
		t.Error("restarted after a failed validate")
	}
}

// A brand-new host in check mode has no <prefix>/data yet; file_storage needs an existing directory, so
// validate must use a temporary data dir (the first CI end-to-end run failed exactly here).
func TestCheckModeNewHostValidatesWithTempData(t *testing.T) {
	h := newHost(t)
	h.write("/opt/monitoring/secrets/collector.env", "OO_ENDPOINT=x\nOO_AUTH=y\nORACLE_MON_PASSWORD=z\n", 0o600)
	r := &fakeRunner{readable: true}
	res, out := run(t, h, r, false, false, true)
	if res.Failures != 0 || !strings.Contains(out, "validate: VALID") {
		t.Fatalf("%s", out)
	}
	data := ""
	for _, kv := range r.envSeen {
		if strings.HasPrefix(kv, "MONITORING_DATA=") {
			data = strings.TrimPrefix(kv, "MONITORING_DATA=")
		}
	}
	if data == "" || strings.HasPrefix(data, h.root) {
		t.Errorf("MONITORING_DATA = %q, want a temp dir outside the host", data)
	}
}

func smokeHost(t *testing.T) host {
	h := newHost(t)
	h.write("/opt/monitoring/secrets/collector.env",
		"OO_ENDPOINT='https://backend.example.com'\nOO_AUTH='Basic fake'\nORACLE_MON_PASSWORD='123456'\n", 0o600)
	h.write("/opt/monitoring/bin/monitoring-collector", "BIN", 0o755)
	return h
}

func TestSmokeRunClean(t *testing.T) {
	r := &fakeRunner{readable: true,
		smokeOut: "info starting receiver oracledb\ninfo starting receiver sql_query/oracle\n"}
	res, out := runSmoke(t, smokeHost(t), r, false, false, false, true)
	if res.Failures != 0 || !strings.Contains(out, "2 discovered receivers, no load / start errors") {
		t.Fatalf("%s", out)
	}
	// never the real backend, never the real data dir
	env := strings.Join(r.smokeEnv, " ")
	if strings.Contains(env, "backend.example.com") || !strings.Contains(env, "OO_ENDPOINT=http://127.0.0.1:") ||
		strings.Contains(env, "MONITORING_DATA=/opt/monitoring") {
		t.Errorf("smoke env: %v", r.smokeEnv)
	}
	if !r.has("zz-smoke.yaml") {
		t.Error("smoke overlay (own ports, no telemetry) not passed")
	}
}

func TestSmokeRunCatchesTemplateError(t *testing.T) {
	r := &fakeRunner{readable: true, smokeOut: "info starting receiver\n" +
		`error failed to start receiver {"error": "failed to load \"oracledb\" template config: got unconvertible type 'int'"}` + "\n"}
	res, out := runSmoke(t, smokeHost(t), r, false, false, false, true)
	if res.Failures == 0 || !strings.Contains(out, "1 error line(s) in the smoke run") {
		t.Fatalf("%s", out)
	}
}

func TestSmokeRunStopsAtOracleLoginError(t *testing.T) {
	r := &fakeRunner{readable: true,
		smokeOut: "info starting receiver\nerror ORA-01017: invalid username/password; logon denied\nerror retry again\n"}
	res, out := runSmoke(t, smokeHost(t), r, false, false, false, true)
	if !r.stopped || res.Failures == 0 || !strings.Contains(out, "Oracle rejected the monitoring login") {
		t.Fatalf("stopped=%v\n%s", r.stopped, out)
	}
	if strings.Contains(out, "retry again") {
		t.Error("output after the early stop must not be read")
	}
}

func TestSmokeRunCollectorExits(t *testing.T) {
	r := &fakeRunner{readable: true, smokeOut: "Error: cannot start pipelines\n",
		smokeErr: os.ErrClosed}
	res, out := runSmoke(t, smokeHost(t), r, false, false, false, true)
	if res.Failures == 0 || !strings.Contains(out, "the collector stopped during the smoke run") {
		t.Fatalf("%s", out)
	}
}

func TestSELinuxNothingToDoWhenLabelsAreRight(t *testing.T) {
	if !allBinT([]byte("system_u:object_r:bin_t:s0\nsystem_u:object_r:bin_t:s0\n"), 2) {
		t.Error("two bin_t labels must be ok")
	}
	if allBinT([]byte("system_u:object_r:bin_t:s0\nsystem_u:object_r:usr_t:s0\n"), 2) {
		t.Error("usr_t must need a relabel")
	}
	if allBinT([]byte("system_u:object_r:bin_t:s0\n"), 2) {
		t.Error("a missing file must need a relabel")
	}
}

func TestSELinuxWithoutSemanageWarns(t *testing.T) {
	h := newHost(t)
	r := &fakeRunner{selinux: true}
	_, out := run(t, h, r, false, false, true)
	if !strings.Contains(out, "WARN  semanage not installed") || !strings.Contains(out, "would: chcon -R -t bin_t") {
		t.Errorf("%s", out)
	}
}

func TestLineDiff(t *testing.T) {
	d, add, del := lineDiff("a\nb\nc\nd\n", "a\nB\nc\nd\ne\n")
	if add != 2 || del != 1 || !strings.Contains(d, "-b\n+B\n") || !strings.Contains(d, "+e\n") {
		t.Errorf("diff (+%d -%d):\n%s", add, del, d)
	}
}

// installed writes a previous, working installation.
func installed(t *testing.T) host {
	h := smokeHost(t)
	for _, f := range []string{"config/config.yaml", "config/host.yaml", "systemd/monitoring-collector.service", "VERSION"} {
		h.write("/opt/monitoring/"+f, "old "+f+"\n", 0o644)
	}
	h.write("/opt/monitoring/bin/monitoring-collector", "BIN", 0o755) // = the release's (fakeSource)
	return h
}

func TestRollbackRestoresFilesWhenAUnitDoesNotStart(t *testing.T) {
	needSymlinks(t)
	h := installed(t)
	r := &fakeRunner{readable: true, inactive: 1}
	res, out := run(t, h, r, true, true, false)
	if !res.RolledBack || res.Failures == 0 {
		t.Fatalf("want a rollback with a failure:\n%s", out)
	}
	if got := h.read("/opt/monitoring/config/config.yaml"); got != "old config/config.yaml\n" {
		t.Errorf("config.yaml not restored: %q", got)
	}
	if got := h.read("/opt/monitoring/VERSION"); got != "old VERSION\n" {
		t.Errorf("VERSION not restored: %q", got)
	}
	if _, err := os.Stat(filepath.Join(h.root, "opt/monitoring/config/site.d/10-site.yaml")); err == nil {
		t.Error("a file added by the failed apply survived the rollback")
	}
	fi, err := os.Stat(filepath.Join(h.root, "opt/monitoring/config"))
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("restored config/ must stay 755 (collector reads it): %v %v", fi.Mode(), err)
	}
	for _, want := range []string{"10b. rollback", "files restored from", "rolled back: the previous state runs again",
		"ROLLED BACK:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestRollbackRestoresThePreviousBinary(t *testing.T) {
	needSymlinks(t)
	h := installed(t)
	h.write("/opt/monitoring/bin/monitoring-collector", "OLD-BIN", 0o755) // not the release's -> replaced
	r := &fakeRunner{readable: true, inactive: 1}
	res, out := run(t, h, r, true, true, true)
	if !res.RolledBack {
		t.Fatalf("%s", out)
	}
	if got := h.read("/opt/monitoring/bin/monitoring-collector"); got != "OLD-BIN" {
		t.Errorf("binary not restored: %q", got)
	}
}

func TestRollbackFirstInstallStopsAndDisables(t *testing.T) {
	needSymlinks(t)
	h := smokeHost(t)
	r := &fakeRunner{readable: true, inactive: 99}
	res, out := run(t, h, r, true, true, false)
	if !res.RolledBack || !r.has("systemctl stop") || !r.has("systemctl disable") {
		t.Fatalf("first install must be stopped + disabled:\n%s", out)
	}
	if r.has("systemctl daemon-reload") && strings.Count(strings.Join(r.cmds, "\n"), "systemctl restart") > 1 {
		t.Error("first install must not be restarted again")
	}
}

func TestNoRollbackWhenNothingChanged(t *testing.T) {
	needSymlinks(t)
	h := smokeHost(t)
	if res, out := run(t, h, &fakeRunner{readable: true}, true, true, false); res.Failures != 0 {
		t.Fatalf("first apply: %s", out)
	}
	r := &fakeRunner{readable: true, inactive: 99}
	res, out := run(t, h, r, true, true, false)
	if res.RolledBack || !strings.Contains(out, "nothing to undo") {
		t.Errorf("unchanged apply must not roll back:\n%s", out)
	}
	if r.has("systemctl disable") {
		t.Error("a working installation must never be disabled by a rollback")
	}
}

func uninstallRun(t *testing.T, h host, r *fakeRunner, apply bool, u UninstallOptions) (Result, string) {
	t.Helper()
	var out bytes.Buffer
	res, err := Uninstall(Options{Root: h.root, Apply: apply, SkipRootCheck: true, Out: &out, Runner: r}, u)
	if err != nil {
		t.Fatal(err)
	}
	return res, out.String()
}

func TestUninstallRemovesExactlyWhatApplyRecorded(t *testing.T) {
	needSymlinks(t)
	h := smokeHost(t)
	// a fresh user: drop it from passwd so apply creates it (and records user_created)
	h.write("/etc/passwd", "root:x:0:0::/root:/bin/bash\n", 0o644)
	r := &fakeRunner{}
	if res, out := run(t, h, r, true, false, false); res.Failures != 0 {
		// useradd is faked, so the user does not appear: data dirs fail. Re-add the user and apply again.
		h.write("/etc/passwd", "root:x:0:0::/root:/bin/bash\notelcol-contrib:x:990:990::/opt/monitoring/data:/sbin/nologin\n", 0o644)
		if res, out = run(t, h, r, true, false, false); res.Failures != 0 {
			t.Fatalf("apply: %s", out)
		}
	}
	st := h.read("/opt/monitoring/amc-state.json")
	for _, want := range []string{`"user_created": true`, `"/var/log/app/alert.log"`, `"/var/log/app"`, `"tomcat"`,
		`"monitoring-collector.service"`} {
		if !strings.Contains(st, want) {
			t.Errorf("state lacks %s:\n%s", want, st)
		}
	}
	// check mode changes nothing
	rc := &fakeRunner{}
	if _, out := uninstallRun(t, h, rc, false, UninstallOptions{}); !strings.Contains(out, "would: setfacl -x u:otelcol-contrib /var/log/app/alert.log") {
		t.Errorf("check mode output:\n%s", out)
	}
	if rc.has("systemctl stop") || h.read("/opt/monitoring/VERSION") == "" {
		t.Error("check mode changed something")
	}
	// real uninstall, defaults: keep secrets, data, backup, user
	ru := &fakeRunner{}
	res, out := uninstallRun(t, h, ru, true, UninstallOptions{})
	if res.Failures != 0 {
		t.Fatalf("%s", out)
	}
	for _, c := range []string{"systemctl stop", "systemctl disable", "setfacl -x u:otelcol-contrib /var/log/app/alert.log",
		"setfacl -x u:otelcol-contrib /var/log/app", "gpasswd -d otelcol-contrib tomcat"} {
		if !ru.has(c) {
			t.Errorf("missing %q in %v", c, ru.cmds)
		}
	}
	if ru.has("userdel") {
		t.Error("user removed without --purge")
	}
	for _, gone := range []string{"opt/monitoring/bin", "opt/monitoring/config", "opt/monitoring/amc-state.json",
		"opt/monitoring/inventory.json", // v0.15.0: CI e2e found it left behind (prefix not empty)
		"etc/systemd/system/monitoring-collector.service"} {
		if _, err := os.Lstat(filepath.Join(h.root, gone)); err == nil {
			t.Errorf("%s still there", gone)
		}
	}
	if h.read("/opt/monitoring/secrets/collector.env") == "" {
		t.Error("secrets removed without --purge-secrets")
	}
}

func TestApplyAdoptsACLsFromAnOlderInstaller(t *testing.T) {
	needSymlinks(t)
	h := smokeHost(t)
	r := &fakeRunner{readable: true, acl: true} // readable via an existing ACL
	if res, out := run(t, h, r, true, false, false); res.Failures != 0 {
		t.Fatalf("%s", out)
	}
	st := h.read("/opt/monitoring/amc-state.json")
	if !strings.Contains(st, `"selinux_fcontext": []`) || strings.Contains(st, "null") {
		t.Errorf("empty lists must be [] not null:\n%s", st)
	}
	if !strings.Contains(st, `"/var/log/app/alert.log"`) || !strings.Contains(st, `"user_created": true`) {
		t.Errorf("existing ACL / user (home = prefix/data) not adopted:\n%s", st)
	}
	if r.has("setfacl -m") {
		t.Error("readable file must not get a new ACL")
	}
}

func runWithSecretsInput(t *testing.T, h host, r *fakeRunner, apply bool, in map[string]string, answers []byte) (Result, string) {
	t.Helper()
	var out bytes.Buffer
	d := desired()
	d.Answers = answers
	res, err := Run(context.Background(), Options{
		Root: h.root, Apply: apply, Arch: "amd64", SkipRootCheck: true, RootUID: os.Getuid(), StartWait: time.Millisecond,
		Out: &out, Runner: r, SecretsInput: in,
		Now:   func() time.Time { return time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) },
		Chown: func(string, int, int) error { return nil },
	}, d)
	if err != nil {
		t.Fatal(err)
	}
	return res, out.String()
}

var typed = map[string]string{"OO_ENDPOINT": "https://backend.example.com", "OO_AUTH": "Basic dHlwZWQ=",
	"ORACLE_MON_PASSWORD": "typed123", "UNRELATED": "dropped"}

func TestTypedSecretsStayInMemoryInCheckMode(t *testing.T) {
	h := newHost(t)
	h.write("/opt/monitoring/bin/monitoring-collector", "BIN", 0o755)
	r := &fakeRunner{readable: true}
	res, out := runWithSecretsInput(t, h, r, false, typed, []byte("services: {}\n"))
	if res.Failures != 0 || !strings.Contains(out, "would: write /opt/monitoring/secrets/collector.env (3 keys, root 600)") {
		t.Fatalf("%s", out)
	}
	if _, err := os.Stat(filepath.Join(h.root, "opt/monitoring/secrets/collector.env")); err == nil {
		t.Error("check mode wrote the secrets file")
	}
	if !strings.Contains(strings.Join(r.envSeen, " "), "ORACLE_MON_PASSWORD=typed123") {
		t.Error("validate must get the typed secrets")
	}
	if strings.Contains(out, "typed123") || strings.Contains(out, "dHlwZWQ=") {
		t.Errorf("a typed secret was printed:\n%s", out)
	}
	if !strings.Contains(out, "NEW    answers.yaml") {
		t.Errorf("answers.yaml must be a managed file:\n%s", out)
	}
}

func TestTypedSecretsWrittenRoot600OnApply(t *testing.T) {
	needSymlinks(t)
	h := newHost(t)
	h.write("/opt/monitoring/bin/monitoring-collector", "BIN", 0o755)
	r := &fakeRunner{readable: true}
	if res, out := runWithSecretsInput(t, h, r, true, typed, []byte("services: {}\n")); res.Failures != 0 {
		t.Fatalf("%s", out)
	}
	p := filepath.Join(h.root, "opt/monitoring/secrets/collector.env")
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("secrets file: %v %v", fi, err)
	}
	b, _ := os.ReadFile(p)
	want := "OO_ENDPOINT='https://backend.example.com'\nOO_AUTH='Basic dHlwZWQ='\nORACLE_MON_PASSWORD='typed123'\n"
	if string(b) != want {
		t.Errorf("secrets file = %q (only the wanted keys, in order)", b)
	}
	if h.read("/opt/monitoring/answers.yaml") != "services: {}\n" {
		t.Error("answers.yaml not written")
	}
}

func TestTypedSecretsMissingKeyFails(t *testing.T) {
	h := newHost(t)
	r := &fakeRunner{}
	res, out := runWithSecretsInput(t, h, r, false, map[string]string{"OO_ENDPOINT": "x"}, nil)
	if res.Failures == 0 || !strings.Contains(out, "key OO_AUTH missing") {
		t.Errorf("%s", out)
	}
}

func TestCheckCountsChanges(t *testing.T) {
	needSymlinks(t)
	h := smokeHost(t)
	r := &fakeRunner{readable: true}
	if res, out := run(t, h, r, false, false, false); res.Changes == 0 {
		t.Fatalf("a first check must report changes:\n%s", out)
	}
	if res, out := run(t, h, r, true, true, false); res.Failures != 0 {
		t.Fatalf("apply: %s", out)
	}
	// the fake runner does not edit /etc/group: do what the real usermod -aG did
	h.write("/etc/group", "root:x:0:\ntomcat:x:992:otelcol-contrib\notelcol-contrib:x:990:\n", 0o644)
	if res, out := run(t, h, r, false, false, false); res.Changes != 0 {
		t.Errorf("check after apply: %d changes, want 0 (amc update would restart for nothing):\n%s", res.Changes, out)
	}
	// a new installer, identical configuration: only VERSION differs
	h.write("/opt/monitoring/VERSION", "installer=amc older\n", 0o644)
	if res, out := run(t, h, r, false, false, false); res.Changes != 1 || !res.NoRestart {
		t.Errorf("only VERSION changed: changes %d, NoRestart %v, want 1 / true:\n%s", res.Changes, res.NoRestart, out)
	}
	// v0.15.0: the inventory (a new webapp found by the scan) is not read by any unit either
	h.write("/opt/monitoring/inventory.json", "{}\n", 0o644)
	if res, out := run(t, h, r, false, false, false); res.Changes != 1 || !res.NoRestart {
		t.Errorf("VERSION + inventory.json changed: changes %d, NoRestart %v, want 1 / true:\n%s", res.Changes, res.NoRestart, out)
	}
	h.write("/opt/monitoring/config/host.yaml", "receivers: {x: 1}\n", 0o644)
	if res, out := run(t, h, r, false, false, false); res.Changes != 1 || res.NoRestart {
		t.Errorf("VERSION + host.yaml changed: changes %d (one files step), NoRestart %v, want 1 / false:\n%s", res.Changes, res.NoRestart, out)
	}
}

func TestCheckHint(t *testing.T) {
	for hint, want := range map[string]string{"": "Run `amc apply` to change things.", "-": "warning(s).\n", "Run x.": "warning(s). Run x.\n"} {
		var out bytes.Buffer
		_, err := Run(context.Background(), Options{Root: smokeHost(t).root, SkipRootCheck: true, RootUID: os.Getuid(),
			Arch: "amd64", Out: &out, Runner: &fakeRunner{readable: true}, CheckHint: hint, Collector: fakeSource{},
			Chown: func(string, int, int) error { return nil }}, desired())
		if err != nil || !strings.Contains(out.String(), "CHECK done: 0 failures, 0 warning(s)") || !strings.Contains(out.String(), want) {
			t.Errorf("hint %q: want %q in the output (err %v):\n%s", hint, want, err, out.String())
		}
	}
}

// legacyHost is a host on the layout before v0.19.0: otelcol-contrib + four helper units, all linked.
func legacyHost(t *testing.T) host {
	h := smokeHost(t)
	os.Remove(filepath.Join(h.root, "opt/monitoring/bin/monitoring-collector"))
	h.write("/opt/monitoring/bin/otelcol-contrib", "OTELCOL", 0o755)
	h.write("/opt/monitoring/config/config.yaml", "old config\n", 0o644)
	for _, u := range assets.LegacyUnits {
		h.write("/opt/monitoring/systemd/"+u+".service", "old unit "+u+"\n", 0o644)
		link := filepath.Join(h.root, "etc/systemd/system", u+".service")
		os.MkdirAll(filepath.Dir(link), 0o755)
		if err := os.Symlink("/opt/monitoring/systemd/"+u+".service", link); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range assets.LegacyScripts {
		h.write("/opt/monitoring/"+s, "#!/bin/bash\n", 0o755)
	}
	return h
}

func linked(h host, unit string) bool {
	_, err := os.Lstat(filepath.Join(h.root, "etc/systemd/system", unit))
	return err == nil
}

func TestSwitchFromOtelcolContrib(t *testing.T) {
	needSymlinks(t)
	h := legacyHost(t)
	r := &fakeRunner{readable: true}
	res, out := run(t, h, r, true, true, true)
	if res.Failures != 0 || res.RolledBack {
		t.Fatalf("switch failed:\n%s", out)
	}
	for _, u := range assets.LegacyUnits {
		if !r.has("systemctl disable --now "+u+".service") || linked(h, u+".service") {
			t.Errorf("%s not stopped / disabled / unlinked", u)
		}
		if h.read("/opt/monitoring/backup/20261005-120000/systemd/"+u+".service") == "" {
			t.Errorf("%s not in the backup", u)
		}
		if _, err := os.Stat(filepath.Join(h.root, "opt/monitoring/systemd", u+".service")); err == nil {
			t.Errorf("unit file %s not removed", u)
		}
	}
	for _, s := range assets.LegacyScripts {
		if _, err := os.Stat(filepath.Join(h.root, "opt/monitoring", s)); err == nil {
			t.Errorf("%s not removed", s)
		}
	}
	if !linked(h, "monitoring-collector.service") || h.read("/opt/monitoring/bin/monitoring-collector") != "BIN" {
		t.Errorf("new collector not installed / linked:\n%s", out)
	}
	if h.read("/opt/monitoring/bin/otelcol-contrib") != "OTELCOL" {
		t.Error("the old binary must stay until the next release (a manual downgrade needs it)")
	}
	for _, want := range []string{"STOP   monitoring-otelcol.service (replaced by monitoring-collector",
		"REMOVE netconn/otel-sshd.sh (replaced by monitoring-collector"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	st := h.read("/opt/monitoring/" + StateFile)
	if strings.Contains(st, "monitoring-otelcol") || !strings.Contains(st, "monitoring-collector.service") {
		t.Errorf("state units: %s", st)
	}
}

func TestSwitchRollbackBringsTheOldUnitsBack(t *testing.T) {
	needSymlinks(t)
	h := legacyHost(t)
	r := &fakeRunner{readable: true, inactive: 1} // monitoring-collector does not start
	res, out := run(t, h, r, true, true, true)
	if !res.RolledBack {
		t.Fatalf("want a rollback:\n%s", out)
	}
	for _, u := range assets.LegacyUnits {
		link, err := os.Readlink(filepath.Join(h.root, "etc/systemd/system", u+".service"))
		if err != nil || link != "/opt/monitoring/systemd/"+u+".service" {
			t.Errorf("%s not linked again: %q %v", u, link, err)
		}
		if h.read("/opt/monitoring/systemd/"+u+".service") != "old unit "+u+"\n" {
			t.Errorf("%s unit file not restored", u)
		}
	}
	if h.read("/opt/monitoring/netconn/otel-sshd.sh") != "#!/bin/bash\n" || h.read("/opt/monitoring/config/config.yaml") != "old config\n" {
		t.Error("helper scripts / config not restored")
	}
	if linked(h, "monitoring-collector.service") || !r.has("systemctl disable --now monitoring-collector.service") {
		t.Error("the new collector unit must be stopped, disabled and unlinked")
	}
	if !r.has("systemctl enable monitoring-otelcol.service monitoring-netconn.service") ||
		!r.has("systemctl restart monitoring-otelcol.service monitoring-netconn.service monitoring-kmsg.service monitoring-procs.service monitoring-sshd.service") {
		t.Errorf("old units not enabled + restarted: %v", r.cmds)
	}
	if !strings.Contains(out, "rolled back: the previous state runs again") {
		t.Errorf("%s", out)
	}
	st := h.read("/opt/monitoring/" + StateFile)
	if !strings.Contains(st, "monitoring-otelcol.service") || strings.Contains(st, "monitoring-collector.service") {
		t.Errorf("state units after the rollback: %s", st)
	}
}

func TestSwitchNeedsStart(t *testing.T) {
	needSymlinks(t)
	h := legacyHost(t)
	r := &fakeRunner{readable: true}
	res, out := run(t, h, r, true, false, true)
	if res.Failures == 0 || !strings.Contains(out, "run with --start") || r.has("systemctl disable") {
		t.Fatalf("apply without --start must refuse the switch:\n%s", out)
	}
	if !linked(h, "monitoring-otelcol.service") {
		t.Error("old units must stay")
	}
}

// validate fails after the old units were already stopped: never leave the host without monitoring
func TestSwitchValidateFailureRollsBack(t *testing.T) {
	needSymlinks(t)
	h := legacyHost(t)
	r := &fakeRunner{readable: true, validate: os.ErrInvalid}
	res, out := run(t, h, r, true, true, true)
	if !res.RolledBack || res.Failures == 0 || !strings.Contains(out, "The old collector runs again") {
		t.Fatalf("want a rollback:\n%s", out)
	}
	if !linked(h, "monitoring-otelcol.service") || h.read("/opt/monitoring/config/config.yaml") != "old config\n" ||
		!r.has("systemctl restart monitoring-otelcol.service") {
		t.Errorf("old state not back:\n%s", out)
	}
	if r.has("systemctl restart monitoring-collector.service") {
		t.Error("the new unit was never linked: it must not be restarted")
	}
}
