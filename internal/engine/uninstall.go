package engine

import (
	"errors"
	"fmt"
	"os"
)

// UninstallOptions: what to remove besides the installation itself. Defaults keep everything that cannot
// be recreated (secrets, queued data, backups, the user).
type UninstallOptions struct {
	PurgeData    bool // data/ (queue, log bookmarks) and backup/
	PurgeSecrets bool // secrets/ (the caller must have asked the operator first)
	PurgeUser    bool // the collector user, only if amc created / adopted it
}

// Uninstall removes what amc installed, using amc-state.json for everything outside <prefix>. Check mode
// (o.Apply false) prints what it would do.
func Uninstall(o Options, u UninstallOptions) (Result, error) {
	if o.Prefix == "" {
		o.Prefix = "/opt/monitoring"
	}
	if o.User == "" {
		o.User = "otelcol-contrib"
	}
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if o.Runner == nil {
		return Result{}, errors.New("engine: no Runner")
	}
	if !o.SkipRootCheck && os.Geteuid() != 0 {
		return Result{}, errors.New("run as root (sudo)")
	}
	e := &eng{o: o, r: report{w: o.Out}}
	st, found := e.loadState()
	e.st = st
	mode := "CHECK only (nothing is changed)"
	if o.Apply {
		mode = "uninstall"
	}
	fmt.Fprintf(o.Out, "prefix: %s   mode: %s\n", o.Prefix, mode)
	if _, err := os.Stat(e.fs(o.Prefix)); err != nil {
		fmt.Fprintf(o.Out, "\nnothing installed in %s\n", o.Prefix)
		return Result{}, nil
	}
	if !found {
		e.r.warn("%s not found: units and files are removed, but ACLs / groups / SELinux rules from an older "+
			"installer are not known and stay (run `amc apply` once first to record them)", StateFile)
	}
	if st.User != "" && st.User != o.User {
		e.r.warn("state file is for user %s, removing that one", st.User)
		e.o.User = st.User
	}

	e.r.step("1. systemd units")
	units := st.Units
	if len(units) == 0 {
		units = unitFiles()
	}
	e.doCmd("systemctl", append([]string{"stop"}, units...)...)
	e.doCmd("systemctl", append([]string{"disable"}, units...)...)
	for _, n := range units {
		link := "/etc/systemd/system/" + n
		if _, err := os.Lstat(e.fs(link)); err == nil {
			e.do("remove "+link, func() error { return os.Remove(e.fs(link)) })
		}
	}
	e.doCmd("systemctl", "daemon-reload")

	e.r.step("2. read access + groups (from %s)", StateFile)
	for _, f := range st.ACLFiles {
		e.removeACL(f)
	}
	for i := len(st.ACLDirs) - 1; i >= 0; i-- { // deepest first
		e.removeACL(st.ACLDirs[i])
	}
	for _, g := range st.Groups {
		e.doCmd("gpasswd", "-d", e.o.User, g)
	}
	if len(st.ACLFiles)+len(st.ACLDirs)+len(st.Groups) == 0 {
		e.r.ok("nothing recorded")
	}

	e.r.step("3. SELinux rules")
	if len(st.FContexts) == 0 {
		e.r.ok("nothing recorded")
	}
	for _, p := range st.FContexts {
		e.doCmd("semanage", "fcontext", "-d", p)
	}

	e.r.step("4. files in %s", o.Prefix)
	remove := []string{"bin", "config", "systemd", "netconn", "VERSION", StateFile}
	keep := []string{}
	if u.PurgeData {
		remove = append(remove, "data", "backup")
	} else {
		keep = append(keep, "data", "backup")
	}
	if u.PurgeSecrets {
		remove = append(remove, "secrets")
	} else {
		keep = append(keep, "secrets")
	}
	for _, rel := range remove {
		p := e.pre(rel)
		if _, err := os.Lstat(e.fs(p)); err != nil {
			continue
		}
		e.do("remove "+p, func() error { return os.RemoveAll(e.fs(p)) })
	}
	for _, rel := range keep {
		if _, err := os.Stat(e.fs(e.pre(rel))); err == nil {
			e.r.ok("kept %s (remove with %s)", e.pre(rel), purgeFlag(rel))
		}
	}
	if len(keep) == 0 {
		e.do("remove "+o.Prefix+" (if empty)", func() error {
			err := os.Remove(e.fs(o.Prefix))
			if err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("not empty, kept: %w", err)
			}
			return nil
		})
	}

	e.r.step("5. collector user")
	switch {
	case !u.PurgeUser:
		e.r.ok("kept user %s (remove with --purge)", e.o.User)
	case !st.UserCreated:
		e.r.warn("user %s was not created by amc: kept", e.o.User)
	default:
		e.doCmd("userdel", e.o.User)
	}

	res := Result{Failures: e.r.failures, Warnings: e.r.warnings, Applied: o.Apply}
	switch {
	case !o.Apply:
		fmt.Fprintf(o.Out, "\nCHECK done: %d failure(s), %d warning(s). Run `amc uninstall --yes` to remove.\n",
			res.Failures, res.Warnings)
	default:
		fmt.Fprintf(o.Out, "\nUNINSTALLED: %d failure(s), %d warning(s).\n", res.Failures, res.Warnings)
	}
	return res, nil
}

func (e *eng) removeACL(p string) {
	if _, err := os.Stat(e.fs(p)); err != nil {
		e.r.ok("gone already: %s", p)
		return
	}
	e.doCmd("setfacl", "-x", "u:"+e.o.User, p)
}

func purgeFlag(rel string) string {
	switch rel {
	case "secrets":
		return "--purge-secrets"
	default:
		return "--purge-data"
	}
}
