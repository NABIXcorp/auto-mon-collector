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
}

func (f *fakeRunner) Run(name string, args ...string) error {
	c := name + " " + strings.Join(args, " ")
	f.cmds = append(f.cmds, c)
	switch {
	case name == "selinuxenabled" && !f.selinux:
		return os.ErrNotExist
	case name == "runuser" && !f.readable:
		return os.ErrPermission
	}
	return nil
}

func (f *fakeRunner) Output(env []string, name string, args ...string) ([]byte, error) {
	f.cmds = append(f.cmds, "OUT "+filepath.Base(name)+" "+strings.Join(args, " "))
	switch {
	case len(args) == 1 && args[0] == "--version":
		return []byte("otelcol-contrib version " + f.version + "\n"), nil
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
	t.Helper()
	var out bytes.Buffer
	res, err := Run(context.Background(), Options{
		Root: h.root, Apply: apply, Start: start, Fetch: fetch, Arch: "amd64",
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
