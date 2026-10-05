// Package engine installs a generated host configuration into <prefix> (default /opt/monitoring).
//
// It is a Go port of the install.sh that ran this layout in production, step for step:
//
//	1 preflight  2 user + dirs  3 secrets (keys only)  4 collector binary  5 files (diff, backup, write)
//	6 SELinux  7 read access (single-file ACLs, groups)  8 validate  9 systemd units  10 start + check
//
// Without Options.Apply nothing on the system changes ("check mode"): every action is printed as "would:".
// Filesystem changes are made in Go below Options.Root (so tests run in a temp dir); system tools (useradd,
// setfacl, semanage, systemctl, ...) go through Options.Runner. Secret values are never printed.
package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/assets"
	"github.com/NABIXcorp/auto-mon-collector/internal/collector"
	"github.com/NABIXcorp/auto-mon-collector/internal/envfile"
)

// Runner runs system tools. Run = exit status only; Output = combined output (read-only tools, validate).
type Runner interface {
	Run(name string, args ...string) error
	Output(env []string, name string, args ...string) ([]byte, error)
	LookPath(name string) bool
}

// Options control one engine run.
type Options struct {
	Prefix string // default /opt/monitoring
	User   string // default otelcol-contrib
	Root   string // filesystem root; "" = the real system (tests use a temp dir)
	Arch   string // default runtime.GOARCH

	Apply bool // change the system (otherwise check mode)
	Start bool // with Apply: (re)start the units and check them
	Fetch bool // download the pinned collector if missing / other version

	SkipRootCheck bool          // tests only
	RootUID       int           // uid that must own the secrets file; 0 = root (tests use their own uid)
	StartWait     time.Duration // default 20 s
	Out           io.Writer
	Runner        Runner
	Now           func() time.Time
	Chown         func(path string, uid, gid int) error
	Fetcher       func(context.Context, collector.Asset, string) (string, error)
}

// Desired is what the generator (or an operator) wants on the host.
type Desired struct {
	HostYAML   []byte
	HostEnv    []byte
	Site       map[string][]byte // config/site.d/<name> overlay files
	SecretKeys []string          // keys that must be present in secrets/collector.env
	ReadFiles  []string          // files the collector must read (ACL u:<user>:r, traverse on parents)
	Groups     []string          // extra groups for the collector user (e.g. the Tomcat group for its logs)
	Version    []byte            // VERSION file content
}

// Result of a run.
type Result struct {
	Failures, Warnings int
	Applied            bool
}

type file struct {
	rel  string
	data []byte
	mode os.FileMode
}

type eng struct {
	o       Options
	d       Desired
	r       report
	secrets map[string]string // values: never printed
	bin     string            // collector binary usable for validate ("" = none)
	files   []file
}

const backupsKept = 10

// Run executes the steps. A returned error means the run could not even start (e.g. not root).
func Run(ctx context.Context, o Options, d Desired) (Result, error) {
	if o.Prefix == "" {
		o.Prefix = "/opt/monitoring"
	}
	if o.User == "" {
		o.User = "otelcol-contrib"
	}
	if o.Arch == "" {
		o.Arch = runtime.GOARCH
	}
	if o.StartWait == 0 {
		o.StartWait = 20 * time.Second
	}
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Chown == nil {
		o.Chown = os.Lchown
	}
	if o.Fetcher == nil {
		o.Fetcher = collector.Fetch
	}
	if o.Runner == nil {
		return Result{}, errors.New("engine: no Runner")
	}
	if o.Start && !o.Apply {
		return Result{}, errors.New("start needs apply")
	}
	if !o.SkipRootCheck && os.Geteuid() != 0 {
		return Result{}, errors.New("run as root (sudo)")
	}
	e := &eng{o: o, d: d, r: report{w: o.Out}}
	mode := "CHECK only (nothing is changed)"
	if o.Apply {
		mode = "apply"
		if o.Start {
			mode += " + start"
		}
	}
	fmt.Fprintf(o.Out, "prefix: %s   mode: %s\n", o.Prefix, mode)

	tmp, err := os.MkdirTemp("", "amc-")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(tmp)

	for _, step := range []func(context.Context, string) bool{
		e.preflight, e.userAndDirs, e.checkSecrets, e.collectorBinary, e.installFiles,
		e.selinux, e.readAccess, e.validate,
	} {
		if !step(ctx, tmp) {
			break
		}
	}
	res := Result{Failures: e.r.failures, Warnings: e.r.warnings}
	if e.r.failures > 0 {
		fmt.Fprintf(o.Out, "\nSTOP: %d failure(s), %d warning(s). Nothing restarted.\n", e.r.failures, e.r.warnings)
		return res, nil
	}
	if !o.Apply {
		fmt.Fprintf(o.Out, "\nCHECK done: 0 failures, %d warning(s). Run `amc apply` to change things.\n", e.r.warnings)
		return res, nil
	}
	e.units()
	if o.Start && e.r.failures == 0 {
		e.start(ctx)
	}
	res = Result{Failures: e.r.failures, Warnings: e.r.warnings, Applied: true}
	ver := strings.ReplaceAll(strings.TrimSpace(string(d.Version)), "\n", " ")
	fmt.Fprintf(o.Out, "\nDONE: %d failure(s), %d warning(s). Installed: %s\n", res.Failures, res.Warnings, ver)
	return res, nil
}

// ---- helpers --------------------------------------------------------------------------------------------

// fs maps an absolute system path to the filesystem below Options.Root.
func (e *eng) fs(p string) string { return filepath.Join(e.o.Root, filepath.FromSlash(p)) }
func (e *eng) pre(rel ...string) string {
	return path.Join(append([]string{e.o.Prefix}, rel...)...)
}

// do runs fn in apply mode and reports "done", or only reports "would:" in check mode.
func (e *eng) do(desc string, fn func() error) bool {
	if !e.o.Apply {
		e.r.would("%s", desc)
		return true
	}
	if err := fn(); err != nil {
		e.r.fail("%s: %v", desc, err)
		return false
	}
	e.r.done("%s", desc)
	return true
}

func (e *eng) cmd(name string, args ...string) (string, func() error) {
	return name + " " + strings.Join(args, " "), func() error { return e.o.Runner.Run(name, args...) }
}

func (e *eng) doCmd(name string, args ...string) bool {
	desc, fn := e.cmd(name, args...)
	return e.do(desc, fn)
}

// lookupUser reads <root>/etc/passwd.
func (e *eng) lookupUser(name string) (uid, gid int, ok bool) {
	b, err := os.ReadFile(e.fs("/etc/passwd"))
	if err != nil {
		return 0, 0, false
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, ":")
		if len(f) >= 4 && f[0] == name {
			uid, err1 := strconv.Atoi(f[2])
			gid, err2 := strconv.Atoi(f[3])
			return uid, gid, err1 == nil && err2 == nil
		}
	}
	return 0, 0, false
}

// groupMembers returns the groups (from <root>/etc/group) that list user as a member.
func (e *eng) groupMembers(user string) map[string]bool {
	out := map[string]bool{}
	b, _ := os.ReadFile(e.fs("/etc/group"))
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 4 {
			continue
		}
		for _, m := range strings.Split(f[3], ",") {
			if m == user {
				out[f[0]] = true
			}
		}
	}
	return out
}

func (e *eng) mkdir(p string, mode os.FileMode, uid, gid int) error {
	if err := os.MkdirAll(e.fs(p), mode); err != nil {
		return err
	}
	if err := os.Chmod(e.fs(p), mode); err != nil {
		return err
	}
	return e.o.Chown(e.fs(p), uid, gid)
}

// writeFile writes atomically (temp file + rename) with mode and owner root.
func (e *eng) writeFile(p string, data []byte, mode os.FileMode) error {
	dst := e.fs(p)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".amc-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), mode)
	}
	if err == nil {
		err = e.o.Chown(tmp.Name(), 0, 0)
	}
	if err == nil {
		err = os.Rename(tmp.Name(), dst)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// mask hides secret values in tool output before it is printed.
func (e *eng) mask(s string) string {
	for _, v := range e.secrets {
		if len(v) >= 4 {
			s = strings.ReplaceAll(s, v, "***")
		}
	}
	return s
}

// ---- 1. preflight ---------------------------------------------------------------------------------------

func (e *eng) preflight(context.Context, string) bool {
	e.r.step("1. preflight")
	if _, err := collector.For(e.o.Arch); err != nil {
		e.r.fail("%v", err)
	} else {
		e.r.ok("CPU %s, OS %s", e.o.Arch, e.osName())
	}
	if e.o.Runner.LookPath("systemctl") {
		e.r.ok("systemd present")
	} else {
		e.r.fail("systemd missing (systemctl not found)")
	}
	files, err := e.desiredFiles()
	if err != nil {
		e.r.fail("render files: %v", err)
	}
	e.files = files
	for _, f := range files {
		if bytes.Contains(f.data, []byte("\r")) {
			e.r.fail("Windows line endings (CR) in %s", f.rel)
		}
	}
	if _, err := envfile.Parse(e.d.HostEnv); err != nil {
		e.r.fail("host.env: %v", err)
	}
	return e.r.failures == 0
}

func (e *eng) osName() string {
	b, err := os.ReadFile(e.fs("/etc/os-release"))
	if err != nil {
		return "unknown"
	}
	env, err := envfile.Parse(b)
	if err != nil || env["PRETTY_NAME"] == "" {
		return "unknown"
	}
	return env["PRETTY_NAME"]
}

func (e *eng) desiredFiles() ([]file, error) {
	var site []string
	for n := range e.d.Site {
		if strings.ContainsAny(n, "/\\") || n == "" || n[0] == '.' {
			return nil, fmt.Errorf("invalid site.d file name %q", n)
		}
		site = append(site, n)
	}
	sort.Strings(site)
	var siteAbs []string
	for _, n := range site {
		siteAbs = append(siteAbs, e.pre("config/site.d", n))
	}
	ud := assets.UnitData{Prefix: e.o.Prefix, User: e.o.User, SiteConfigs: siteAbs}
	files := []file{
		{"config/config.yaml", assets.BaseConfig(), 0o644},
		{"config/host.yaml", e.d.HostYAML, 0o644},
		{"config/host.env", e.d.HostEnv, 0o644},
	}
	for _, n := range site {
		files = append(files, file{"config/site.d/" + n, e.d.Site[n], 0o644})
	}
	for _, u := range assets.UnitNames {
		b, err := assets.Unit(u, ud)
		if err != nil {
			return nil, err
		}
		files = append(files, file{"systemd/" + u + ".service", b, 0o644})
	}
	files = append(files,
		file{"netconn/otel-netconn.sh", assets.Netconn(), 0o755},
		file{"VERSION", e.d.Version, 0o644})
	return files, nil
}

// ---- 2. user + directories ------------------------------------------------------------------------------

func (e *eng) userAndDirs(context.Context, string) bool {
	e.r.step("2. system user + directories")
	if uid, gid, ok := e.lookupUser(e.o.User); ok {
		var gs []string
		for g := range e.groupMembers(e.o.User) {
			gs = append(gs, g)
		}
		sort.Strings(gs)
		extra := "none"
		if len(gs) > 0 {
			extra = strings.Join(gs, ",")
		}
		e.r.ok("user %s exists (uid=%d gid=%d, extra groups: %s)", e.o.User, uid, gid, extra)
	} else {
		e.doCmd("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", e.pre("data"),
			"--shell", e.nologin(), e.o.User)
	}
	uid, gid, haveUser := e.lookupUser(e.o.User)
	for _, d := range []string{"", "bin", "config", "config/site.d", "systemd", "netconn", "backup"} {
		e.dir(e.pre(d), 0o755, 0, 0)
	}
	for _, d := range []string{"data", "data/file_storage", "data/netconn"} {
		if !haveUser && e.o.Apply {
			e.r.fail("%s: user %s missing", e.pre(d), e.o.User)
			continue
		}
		e.dir(e.pre(d), 0o750, uid, gid)
	}
	e.dir(e.pre("secrets"), 0o700, 0, 0)
	return true
}

func (e *eng) dir(p string, mode os.FileMode, uid, gid int) {
	if fi, err := os.Stat(e.fs(p)); err == nil && fi.IsDir() {
		e.r.ok("%s", p)
		return
	}
	e.do(fmt.Sprintf("mkdir -m %o %s (owner %d:%d)", mode, p, uid, gid), func() error { return e.mkdir(p, mode, uid, gid) })
}

func (e *eng) nologin() string {
	for _, p := range []string{"/usr/sbin/nologin", "/sbin/nologin"} {
		if _, err := os.Stat(e.fs(p)); err == nil {
			return p
		}
	}
	return "/bin/false"
}

// ---- 3. secrets -----------------------------------------------------------------------------------------

func (e *eng) checkSecrets(context.Context, string) bool {
	e.r.step("3. secrets (keys only, values are never shown)")
	p := e.pre("secrets/collector.env")
	fi, err := os.Stat(e.fs(p))
	if err != nil || fi.Size() == 0 {
		e.r.fail("%s missing: needs %s (root, mode 600)", p, strings.Join(e.d.SecretKeys, " "))
		return true
	}
	if ok, is := rootOnly600(fi, e.o.RootUID); ok {
		e.r.ok("%s root 600", p)
	} else {
		e.r.fail("%s must be owned by root with mode 600 (is %s)", p, is)
	}
	b, err := os.ReadFile(e.fs(p))
	if err != nil {
		e.r.fail("read %s: %v", p, err)
		return true
	}
	env, err := envfile.Parse(b)
	if err != nil {
		e.r.fail("%s: %v", p, err)
		return true
	}
	e.secrets = env
	missing := map[string]bool{}
	for _, k := range envfile.Missing(env, e.d.SecretKeys) {
		missing[k] = true
	}
	for _, k := range e.d.SecretKeys {
		if missing[k] {
			e.r.fail("key %s missing or empty", k)
		} else {
			e.r.ok("key %s present", k)
		}
	}
	return true
}

// ---- 4. collector binary --------------------------------------------------------------------------------

func (e *eng) collectorBinary(ctx context.Context, tmp string) bool {
	e.r.step("4. collector binary %s (%s)", collector.Version, e.o.Arch)
	bin := e.pre("bin/otelcol-contrib")
	have := ""
	if _, err := os.Stat(e.fs(bin)); err == nil {
		out, _ := e.o.Runner.Output(nil, e.fs(bin), "--version")
		have = collector.ParseVersion(out)
	}
	if have == collector.Version {
		e.r.ok("%s is %s", bin, have)
		e.bin = e.fs(bin)
		return true
	}
	if !e.o.Fetch {
		e.r.fail("%s is %q, not %s (fetch is off)", bin, have, collector.Version)
		return true
	}
	asset, err := collector.For(e.o.Arch)
	if err != nil {
		e.r.fail("%v", err)
		return true
	}
	// Check mode downloads too (into a temp dir, nothing installed) so the NEW config can be validated
	// with the real binary on a host that has none yet.
	got, err := e.o.Fetcher(ctx, asset, tmp)
	if err != nil {
		e.r.fail("download %s: %v", asset.URL, err)
		return true
	}
	e.r.ok("downloaded %s, sha256 verified", path.Base(asset.URL))
	e.bin = got
	e.do("install "+bin+" (mode 755, root)", func() error {
		data, err := os.ReadFile(got)
		if err != nil {
			return err
		}
		if err := e.writeFile(bin, data, 0o755); err != nil {
			return err
		}
		e.bin = e.fs(bin)
		return nil
	})
	return true
}

// ---- 5. files -------------------------------------------------------------------------------------------

func (e *eng) installFiles(context.Context, string) bool {
	e.r.step("5. files (diff = what would change)")
	changed := false
	for _, f := range e.files {
		p := e.pre(f.rel)
		old, err := os.ReadFile(e.fs(p))
		switch {
		case err == nil && bytes.Equal(old, f.data):
			e.r.ok("%s unchanged", f.rel)
		case err == nil:
			changed = true
			d, add, del := lineDiff(string(old), string(f.data))
			e.r.line("CHANGE %s (+%d -%d)", f.rel, add, del)
			e.r.indent(e.mask(d), 80)
		default:
			changed = true
			e.r.line("NEW    %s", f.rel)
		}
	}
	stale := e.staleSite()
	for _, n := range stale {
		changed = true
		e.r.line("REMOVE config/site.d/%s (no longer wanted)", n)
	}
	if !changed || !e.o.Apply {
		return true
	}
	if _, err := os.Stat(e.fs(e.pre("config/config.yaml"))); err == nil {
		if b, err := e.backup(); err != nil {
			e.r.fail("backup: %v", err)
			return false
		} else {
			e.r.ok("backup -> %s", b)
		}
	}
	for _, f := range e.files {
		if err := e.writeFile(e.pre(f.rel), f.data, f.mode); err != nil {
			e.r.fail("write %s: %v", f.rel, err)
			return false
		}
	}
	for _, n := range stale {
		if err := os.Remove(e.fs(e.pre("config/site.d", n))); err != nil {
			e.r.fail("remove site.d/%s: %v", n, err)
		}
	}
	e.r.ok("files installed")
	return true
}

func (e *eng) staleSite() []string {
	entries, _ := os.ReadDir(e.fs(e.pre("config/site.d")))
	var out []string
	for _, en := range entries {
		if _, want := e.d.Site[en.Name()]; !want && !en.IsDir() && !strings.HasPrefix(en.Name(), ".") {
			out = append(out, en.Name())
		}
	}
	return out
}

// backup copies config/, systemd/, netconn/ and VERSION to backup/<timestamp>/ and keeps the last 10.
func (e *eng) backup() (string, error) {
	dst := e.pre("backup", e.o.Now().Format("20060102-150405"))
	for _, rel := range []string{"config", "systemd", "netconn", "VERSION"} {
		if err := copyTree(e.fs(e.pre(rel)), filepath.Join(e.fs(dst), rel)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	entries, _ := os.ReadDir(e.fs(e.pre("backup")))
	var names []string
	for _, en := range entries {
		if en.IsDir() && len(en.Name()) == 15 && en.Name()[8] == '-' { // our timestamps only
			names = append(names, en.Name())
		}
	}
	sort.Strings(names)
	for len(names) > backupsKept {
		os.RemoveAll(e.fs(e.pre("backup", names[0])))
		names = names[1:]
	}
	return dst, nil
}

func copyTree(src, dst string) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		if err := os.MkdirAll(dst, 0o700); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, en := range entries {
			if err := copyTree(filepath.Join(src, en.Name()), filepath.Join(dst, en.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	if !fi.Mode().IsRegular() {
		return nil // backups hold regular files only
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	return os.WriteFile(dst, b, fi.Mode().Perm())
}

// ---- 6. SELinux -----------------------------------------------------------------------------------------

func (e *eng) selinux(context.Context, string) bool {
	e.r.step("6. SELinux")
	if e.o.Runner.Run("selinuxenabled") != nil {
		e.r.ok("SELinux not enabled / not present")
		return true
	}
	dirs := []string{e.pre("bin"), e.pre("netconn")}
	// Only act when something is wrong, so a repeated plan shows nothing to do (seen on a real host: a
	// "would: chcon" on every run).
	if e.o.Runner.LookPath("semanage") {
		list, _ := e.o.Runner.Output(nil, "semanage", "fcontext", "-l")
		added := false
		for _, d := range dirs {
			pattern := d + "(/.*)?"
			if bytes.Contains(list, []byte(pattern)) {
				e.r.ok("fcontext %s", pattern)
			} else {
				e.doCmd("semanage", "fcontext", "-a", "-t", "bin_t", pattern)
				added = true
			}
		}
		// restorecon -n -v lists what it would relabel; empty = labels already match the rules
		out, err := e.o.Runner.Output(nil, "restorecon", append([]string{"-R", "-n", "-v"}, dirs...)...)
		if !added && err == nil && len(bytes.TrimSpace(out)) == 0 {
			e.r.ok("labels match the fcontext rules")
		} else {
			e.doCmd("restorecon", append([]string{"-R"}, dirs...)...)
		}
		return true
	}
	e.r.warn("semanage not installed -> chcon (lost on a full relabel; install policycoreutils-python-utils)")
	paths := append(append([]string{}, dirs...), e.pre("bin/otelcol-contrib"), e.pre("netconn/otel-netconn.sh"))
	out, err := e.o.Runner.Output(nil, "stat", append([]string{"-c", "%C"}, paths...)...)
	if err == nil && allBinT(out, len(paths)) {
		e.r.ok("labels are bin_t")
	} else {
		e.doCmd("chcon", append([]string{"-R", "-t", "bin_t"}, dirs...)...)
	}
	return true
}

// allBinT reports whether stat -c %C printed n contexts and every one has the type bin_t.
func allBinT(out []byte, n int) bool {
	lines := strings.Fields(string(out))
	if len(lines) != n {
		return false
	}
	for _, l := range lines {
		if !strings.Contains(l, ":bin_t:") {
			return false
		}
	}
	return true
}

// ---- 7. read access -------------------------------------------------------------------------------------

func (e *eng) readAccess(context.Context, string) bool {
	e.r.step("7. read access")
	_, _, haveUser := e.lookupUser(e.o.User)
	for _, f := range e.d.ReadFiles {
		if _, err := os.Stat(e.fs(f)); err != nil {
			e.r.fail("not found: %s", f)
			continue
		}
		if haveUser && e.o.Runner.Run("runuser", "-u", e.o.User, "--", "test", "-r", f) == nil {
			e.r.ok("readable: %s", f)
			continue
		}
		// traverse (x) on every parent directory, read (r) on this one file only: never admin groups
		var parents []string
		for d := path.Dir(f); d != "/" && d != "."; d = path.Dir(d) {
			parents = append([]string{d}, parents...)
		}
		for _, d := range parents {
			e.doCmd("setfacl", "-m", "u:"+e.o.User+":--x", d)
		}
		e.doCmd("setfacl", "-m", "u:"+e.o.User+":r", f)
	}
	member := e.groupMembers(e.o.User)
	for _, g := range e.d.Groups {
		if member[g] {
			e.r.ok("%s in group %s", e.o.User, g)
		} else {
			e.doCmd("usermod", "-aG", g, e.o.User)
		}
	}
	return true
}

// ---- 8. validate ----------------------------------------------------------------------------------------

func (e *eng) validate(_ context.Context, tmp string) bool {
	e.r.step("8. validate the NEW config (collector binary %s)", collector.Version)
	if e.bin == "" || e.secrets == nil {
		e.r.warn("validate skipped (collector binary or secrets missing)")
		return true
	}
	stage := filepath.Join(tmp, "stage")
	args := []string{"validate"}
	for _, f := range e.files {
		if !strings.HasPrefix(f.rel, "config/") || strings.HasSuffix(f.rel, ".env") {
			continue
		}
		p := filepath.Join(stage, filepath.FromSlash(f.rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			e.r.fail("stage: %v", err)
			return false
		}
		if err := os.WriteFile(p, f.data, 0o600); err != nil {
			e.r.fail("stage: %v", err)
			return false
		}
		args = append(args, "--config="+p)
	}
	// file_storage needs an existing directory. On a new host (check mode) <prefix>/data does not exist yet:
	// validate against a temporary data dir with the same layout instead (found by the CI end-to-end test).
	data := e.fs(e.pre("data"))
	if _, err := os.Stat(filepath.Join(data, "file_storage")); err != nil {
		data = filepath.Join(tmp, "data")
		for _, sub := range []string{"file_storage", "netconn"} {
			if err := os.MkdirAll(filepath.Join(data, sub), 0o700); err != nil {
				e.r.fail("stage: %v", err)
				return false
			}
		}
	}
	hostEnv, _ := envfile.Parse(e.d.HostEnv)
	env := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "MONITORING_DATA=" + data}
	for _, m := range []map[string]string{hostEnv, e.secrets} {
		for k, v := range m {
			env = append(env, k+"="+v)
		}
	}
	out, err := e.o.Runner.Output(env, e.bin, args...)
	if err != nil {
		e.r.fail("validate failed:")
		lines := strings.Split(strings.TrimRight(e.mask(string(out)), "\n"), "\n")
		e.r.indent(strings.Join(lines[max(0, len(lines)-20):], "\n"), 20)
		return false
	}
	e.r.ok("otelcol-contrib validate: VALID")
	return true
}

// ---- 9. units, 10. start --------------------------------------------------------------------------------

func (e *eng) units() {
	e.r.step("9. systemd units")
	var names []string
	for _, u := range assets.UnitNames {
		name := u + ".service"
		names = append(names, name)
		link := e.fs("/etc/systemd/system/" + name)
		target := e.pre("systemd", name)
		if cur, err := os.Readlink(link); err == nil && cur == target {
			continue
		}
		os.Remove(link)
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			e.r.fail("link %s: %v", name, err)
			return
		}
		if err := os.Symlink(target, link); err != nil {
			e.r.fail("link %s: %v", name, err)
			return
		}
	}
	if err := e.o.Runner.Run("systemctl", "daemon-reload"); err != nil {
		e.r.fail("systemctl daemon-reload: %v", err)
		return
	}
	if err := e.o.Runner.Run("systemctl", append([]string{"enable"}, names...)...); err != nil {
		e.r.fail("systemctl enable: %v", err)
		return
	}
	e.r.ok("linked + enabled: %s", strings.Join(names, " "))
}

func (e *eng) start(ctx context.Context) {
	e.r.step("10. restart + check")
	var names []string
	for _, u := range assets.UnitNames {
		names = append(names, u+".service")
	}
	if err := e.o.Runner.Run("systemctl", append([]string{"restart"}, names...)...); err != nil {
		e.r.fail("systemctl restart: %v", err)
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(e.o.StartWait):
	}
	for _, n := range names {
		if e.o.Runner.Run("systemctl", "is-active", "-q", n) == nil {
			e.r.ok("%s active", n)
		} else {
			e.r.fail("%s NOT active: journalctl -u %s", n, n)
		}
	}
	out, _ := e.o.Runner.Output(nil, "journalctl", "-u", names[0], "--since", "-1min", "--no-pager", "-o", "cat")
	var bad []string
	for _, l := range strings.Split(string(out), "\n") {
		ll := strings.ToLower(l)
		if (strings.Contains(ll, "error") || strings.Contains(ll, "warn")) && !strings.Contains(ll, "probe") {
			bad = append(bad, l)
		}
	}
	if len(bad) > 0 {
		e.r.warn("%d error/warn line(s) in the last minute:", len(bad))
		e.r.indent(e.mask(strings.Join(bad[max(0, len(bad)-10):], "\n")), 10)
	}
}
