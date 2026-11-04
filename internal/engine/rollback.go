package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/NABIXcorp/auto-mon-collector/internal/collector"
)

// rollback runs when a unit is not active after apply --start (or when an apply that already stopped the old units
// fails). It only undoes what THIS apply changed:
//
//	first install            -> stop + disable the units (no restart loop); files stay for diagnosis
//	files / binary replaced  -> restore them from the backup / bin/monitoring-collector.previous, restart, check
//	units switched (v0.19.0) -> unlink the new collector unit, link + enable the old collector + helper units again
//	nothing changed          -> nothing to undo: the failure was there before this apply
func (e *eng) rollback(ctx context.Context) {
	e.r.step("10b. rollback (a unit is not active)")
	names := e.unitFiles()
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
		e.r.line("next: journalctl -u %s, fix, then monitoring-agent apply --start again", names[0])
		return
	case e.backupDir == "" && !e.binReplaced && !e.probeBinReplaced && len(e.droppedUnits) == 0 && !e.agentBinMoved && !e.polkitMoved && len(e.moves) == 0:
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
		bin := e.fs(e.pre("bin", collector.Name))
		if err := os.Rename(bin+".previous", bin); err != nil {
			e.r.fail("rollback collector binary: %v", err)
			return
		}
		e.r.ok("previous collector binary restored")
	}
	if e.probeBinReplaced {
		bin := e.fs(e.pre(probeBinRel))
		if err := os.Rename(bin+".previous", bin); err != nil {
			e.r.fail("rollback prober binary: %v", err)
			return
		}
		e.r.ok("previous prober binary restored")
	}
	if e.agentBinMoved {
		old := e.fs(e.pre(legacyAgentBinRel))
		if err := os.Rename(old+".previous", old); err != nil {
			e.r.fail("rollback %s: %v", legacyAgentBinRel, err)
		} else {
			e.r.ok("previous %s restored", legacyAgentBinRel)
		}
	}
	if e.polkitMoved {
		if err := os.Rename(e.fs(LegacyPolkitRule)+".previous", e.fs(LegacyPolkitRule)); err != nil {
			e.r.fail("rollback %s: %v", LegacyPolkitRule, err)
		} else {
			e.st.add(&e.st.Polkit, LegacyPolkitRule)
			e.r.ok("previous polkit rule %s restored", LegacyPolkitRule)
		}
	}
	if e.prevPolkit != nil {
		if err := e.writeFile(PolkitRule, e.prevPolkit, 0o644); err != nil {
			e.r.fail("rollback %s: %v", PolkitRule, err)
		} else {
			e.r.ok("previous polkit rule %s restored", PolkitRule)
		}
	}
	e.undoUserMoves()
	names = e.restoreUnitSet()
	if err := e.o.Runner.Run("systemctl", "daemon-reload"); err != nil {
		e.r.fail("systemctl daemon-reload: %v", err)
		return
	}
	if len(e.droppedUnits) > 0 {
		if err := e.o.Runner.Run("systemctl", append([]string{"enable"}, e.droppedUnits...)...); err != nil {
			e.r.fail("systemctl enable: %v", err)
		}
	}
	e.rolledBack = true
	if e.restartAndCheckUnits(ctx, true, names) {
		e.r.ok("rolled back: the previous state runs again")
	} else {
		e.r.fail("rolled back, but the previous state does not start either: journalctl -u %s", names[0])
	}
}

// restoreUnitSet undoes a unit switch of this apply (v0.19.0: otelcol-contrib + helpers -> monitoring-collector):
// units linked for the first time are stopped, disabled and unlinked; the dropped ones are linked again (their files
// came back from the backup). It returns the units the previous state runs (the old collector first).
func (e *eng) restoreUnitSet() []string {
	if len(e.droppedUnits) == 0 {
		return e.unitFiles()
	}
	added := map[string]bool{}
	for _, name := range e.addedUnits {
		added[name] = true
		e.dropUnit(name, "rollback")
	}
	for _, name := range e.droppedUnits {
		link := e.fs("/etc/systemd/system/" + name)
		os.Remove(link)
		if err := os.Symlink(e.pre("systemd", name), link); err != nil {
			e.r.fail("link %s: %v", name, err)
			continue
		}
		e.st.add(&e.st.Units, name)
	}
	names := append([]string{}, e.droppedUnits...)
	for _, n := range e.unitFiles() {
		if _, err := os.Lstat(e.fs("/etc/systemd/system/" + n)); err == nil && !added[n] {
			names = append(names, n) // e.g. Cloudprober, the agent (an apply that failed early never linked the new unit)
		}
	}
	e.r.ok("units of the previous state linked again: %s", strings.Join(e.droppedUnits, " "))
	return names
}
