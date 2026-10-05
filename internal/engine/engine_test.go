package engine

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/collector"
)

// fakeRunner records commands and answers like a host where everything works.
type fakeRunner struct {
	cmds     []string
	selinux  bool
	semanage bool
	readable bool
	version  string // output of otelcol-contrib --version
	validate error
	envSeen  []string
	smokeOut string // collector output during the smoke run
	smokeEnv []string
	smokeErr error
	stopped  bool // the stop callback asked for an early stop
	inactive int  // the next N `systemctl is-active` calls report "not active"
	acl      bool // getfacl shows an entry for the collector user
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
	case len(args) == 1 && args[0] == "--version":
		return []byte("otelcol-contrib version " + f.version + "\n"), nil
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
		Version:    []byte("installer=amc test\ncollector=" + collector.Version + "\n"),
	}
}

func run(t *testing.T, h host, r *fakeRunner, apply, start, fetch bool) (Result, string) {
	return runSmoke(t, h, r, apply, start, fetch, false)
}

func runSmoke(t *testing.T, h host, r *fakeRunner, apply, start, fetch, smoke bool) (Result, string) {
	t.Helper()
	var out bytes.Buffer
	res, err := Run(context.Background(), Options{
		Root: h.root, Apply: apply, Start: start, Fetch: fetch, Smoke: smoke, Rollback: true, Arch: "amd64",
		SkipRootCheck: true, RootUID: os.Getuid(), StartWait: time.Millisecond, Out: &out, Runner: r,
		Now:   func() time.Time { return time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) },
		Chown: func(string, int, int) error { return nil },
		Fetcher: func(_ context.Context, _ collector.Asset, dir string) (string, error) {
			p := filepath.Join(dir, "otelcol-contrib")
			return p, os.WriteFile(p, []byte("BIN"), 0o755)
		},
	}, desired())
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
	r := &fakeRunner{version: collector.Version, readable: true}
	res, out := run(t, h, r, true, true, true)
	if res.Failures != 0 || !res.Applied {
		t.Fatalf("apply failed:\n%s", out)
	}
	if !strings.Contains(h.read("/opt/monitoring/systemd/monitoring-otelcol.service"),
		"--config=/opt/monitoring/config/site.d/10-site.yaml") {
		t.Error("site.d file not in ExecStart")
	}
	if got := h.read("/opt/monitoring/config/host.env"); got != "ORACLE_MON=on\n" {
		t.Errorf("host.env = %q", got)
	}
	if link, err := os.Readlink(filepath.Join(h.root, "etc/systemd/system/monitoring-otelcol.service")); err != nil ||
		link != "/opt/monitoring/systemd/monitoring-otelcol.service" {
		t.Errorf("unit link = %q, %v", link, err)
	}
	for _, c := range []string{"systemctl enable", "systemctl restart", "systemctl is-active -q monitoring-netconn.service"} {
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
	r2 := &fakeRunner{version: collector.Version, readable: true}
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
	h.write("/opt/monitoring/bin/otelcol-contrib", "BIN", 0o755) // fetch is off in this test
	r := &fakeRunner{version: collector.Version, readable: true}
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
	r := &fakeRunner{version: collector.Version, readable: true, validate: os.ErrInvalid}
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
	h.write("/opt/monitoring/bin/otelcol-contrib", "BIN", 0o755)
	return h
}

func TestSmokeRunClean(t *testing.T) {
	r := &fakeRunner{version: collector.Version, readable: true,
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
	r := &fakeRunner{version: collector.Version, readable: true, smokeOut: "info starting receiver\n" +
		`error failed to start receiver {"error": "failed to load \"oracledb\" template config: got unconvertible type 'int'"}` + "\n"}
	res, out := runSmoke(t, smokeHost(t), r, false, false, false, true)
	if res.Failures == 0 || !strings.Contains(out, "1 error line(s) in the smoke run") {
		t.Fatalf("%s", out)
	}
}

func TestSmokeRunStopsAtOracleLoginError(t *testing.T) {
	r := &fakeRunner{version: collector.Version, readable: true,
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
	r := &fakeRunner{version: collector.Version, readable: true, smokeOut: "Error: cannot start pipelines\n",
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
	for _, f := range []string{"config/config.yaml", "config/host.yaml", "systemd/monitoring-otelcol.service", "VERSION"} {
		h.write("/opt/monitoring/"+f, "old "+f+"\n", 0o644)
	}
	h.write("/opt/monitoring/bin/otelcol-contrib", "OLD-BIN", 0o755)
	return h
}

func TestRollbackRestoresFilesWhenAUnitDoesNotStart(t *testing.T) {
	needSymlinks(t)
	h := installed(t)
	r := &fakeRunner{version: collector.Version, readable: true, inactive: 1}
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
	r := &fakeRunner{version: "0.159.0", readable: true, inactive: 1} // installed binary is older -> replaced
	res, out := run(t, h, r, true, true, true)
	if !res.RolledBack {
		t.Fatalf("%s", out)
	}
	if got := h.read("/opt/monitoring/bin/otelcol-contrib"); got != "OLD-BIN" {
		t.Errorf("binary not restored: %q", got)
	}
}

func TestRollbackFirstInstallStopsAndDisables(t *testing.T) {
	needSymlinks(t)
	h := smokeHost(t)
	r := &fakeRunner{version: collector.Version, readable: true, inactive: 99}
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
	if res, out := run(t, h, &fakeRunner{version: collector.Version, readable: true}, true, true, false); res.Failures != 0 {
		t.Fatalf("first apply: %s", out)
	}
	r := &fakeRunner{version: collector.Version, readable: true, inactive: 99}
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
	r := &fakeRunner{version: collector.Version}
	if res, out := run(t, h, r, true, false, false); res.Failures != 0 {
		// useradd is faked, so the user does not appear: data dirs fail. Re-add the user and apply again.
		h.write("/etc/passwd", "root:x:0:0::/root:/bin/bash\notelcol-contrib:x:990:990::/opt/monitoring/data:/sbin/nologin\n", 0o644)
		if res, out = run(t, h, r, true, false, false); res.Failures != 0 {
			t.Fatalf("apply: %s", out)
		}
	}
	st := h.read("/opt/monitoring/amc-state.json")
	for _, want := range []string{`"user_created": true`, `"/var/log/app/alert.log"`, `"/var/log/app"`, `"tomcat"`,
		`"monitoring-otelcol.service"`} {
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
		"etc/systemd/system/monitoring-otelcol.service"} {
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
	r := &fakeRunner{version: collector.Version, readable: true, acl: true} // readable via an existing ACL
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
	h.write("/opt/monitoring/bin/otelcol-contrib", "BIN", 0o755)
	r := &fakeRunner{version: collector.Version, readable: true}
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
	h.write("/opt/monitoring/bin/otelcol-contrib", "BIN", 0o755)
	r := &fakeRunner{version: collector.Version, readable: true}
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
	r := &fakeRunner{version: collector.Version}
	res, out := runWithSecretsInput(t, h, r, false, map[string]string{"OO_ENDPOINT": "x"}, nil)
	if res.Failures == 0 || !strings.Contains(out, "key OO_AUTH missing") {
		t.Errorf("%s", out)
	}
}
