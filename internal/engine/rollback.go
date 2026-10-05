package engine

import (
	"context"
	"os"
	"path/filepath"
)

// rollback runs when a unit is not active after apply --start. It only undoes what THIS apply changed:
//
//	first install            -> stop + disable the units (no restart loop); files stay for diagnosis
//	files / binary replaced  -> restore them from the backup / bin/otelcol-contrib.previous, restart, check
//	nothing changed          -> nothing to undo: the failure was there before this apply
func (e *eng) rollback(ctx context.Context) {
	e.r.step("10b. rollback (a unit is not active)")
	names := unitFiles()
	switch {
	case e.firstInstall:
		for _, args := range [][]string{append([]string{"stop"}, names...), append([]string{"disable"}, names...)} {
			if err := e.o.Runner.Run("systemctl", args...); err != nil {
				e.r.fail("systemctl %s: %v", args[0], err)
				return
			}
		}
		e.rolledBack = true
		e.r.ok("first install: units stopped and disabled (no restart loop); files kept for diagnosis")
		e.r.line("next: journalctl -u %s, fix, then amc apply --start again", names[0])
		return
	case e.backupDir == "" && !e.binReplaced:
		e.r.line("nothing to undo: this apply changed no file and no binary (the problem existed before)")
		return
	}
	if e.backupDir != "" {
		for _, rel := range []string{"config", "systemd", "netconn"} {
			cur, saved := e.fs(e.pre(rel)), filepath.Join(e.fs(e.backupDir), rel)
			if _, err := os.Stat(saved); err != nil {
				continue
			}
			if err := os.RemoveAll(cur); err != nil {
				e.r.fail("rollback %s: %v", rel, err)
				return
			}
			if err := copyTree(saved, cur); err != nil {
				e.r.fail("rollback %s: %v", rel, err)
				return
			}
		}
		if err := copyTree(filepath.Join(e.fs(e.backupDir), "VERSION"), e.fs(e.pre("VERSION"))); err != nil &&
			!os.IsNotExist(err) {
			e.r.fail("rollback VERSION: %v", err)
			return
		}
		e.r.ok("files restored from %s", e.backupDir)
	}
	if e.binReplaced {
		bin := e.fs(e.pre("bin/otelcol-contrib"))
		if err := os.Rename(bin+".previous", bin); err != nil {
			e.r.fail("rollback collector binary: %v", err)
			return
		}
		e.r.ok("previous collector binary restored")
	}
	if err := e.o.Runner.Run("systemctl", "daemon-reload"); err != nil {
		e.r.fail("systemctl daemon-reload: %v", err)
		return
	}
	e.rolledBack = true
	if e.restartAndCheck(ctx, true) {
		e.r.ok("rolled back: the previous state runs again")
	} else {
		e.r.fail("rolled back, but the previous state does not start either: journalctl -u %s", names[0])
	}
}
