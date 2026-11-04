package engine

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Unix users (v0.21.0, naming standard R2): the collector + prober run as `monitoring`, the agent as
// `monitoring-agent`. Before: otelcol-contrib and amc-agent. A host on the old users is moved in one apply --start:
// the new users are created, get the same groups (Desired.Groups) and the same single-file ACLs (Desired.ReadFiles,
// checked with a real read), data/ and agent/ change owner, the units and the polkit rule name the new users; only
// after the units run again are the old users removed (their ACL entries and group memberships, then userdel - only a
// user this installer created). A failed start puts the old owners and users back.
const (
	DefaultUser     = "monitoring"
	LegacyUser      = "otelcol-contrib"
	LegacyAgentUser = "amc-agent"
)

// userMove: an old user this run replaces by a new one.
type userMove struct {
	old, new   string
	dirs       []string // below the prefix, owner changed (recursively) from old to new
	oldCreated bool     // the installer created (or adopted) the old user: removed after the move
	newCreated bool     // this run created the new user (a rollback removes it again)
}

// planUserMoves: which old users this run moves. Only the default names move (an operator's own --user stays), and
// only a user that belongs to this installation (home = <prefix>/data or <prefix>/agent, as the installer creates it).
func (e *eng) planUserMoves() {
	e.moves = nil
	if e.o.User == DefaultUser {
		if _, _, ok := e.lookupUser(LegacyUser); ok && e.userHome(LegacyUser) == e.pre("data") {
			e.moves = append(e.moves, &userMove{old: LegacyUser, new: DefaultUser, dirs: []string{"data"},
				oldCreated: true}) // home = <prefix>/data: the installer created it (the same rule as the adoption in userAndDirs)
		}
	}
	if e.d.Agent != nil {
		if _, _, ok := e.lookupUser(LegacyAgentUser); ok && e.userHome(LegacyAgentUser) == e.pre("agent") {
			e.moves = append(e.moves, &userMove{old: LegacyAgentUser, new: AgentUser, dirs: []string{"agent"},
				oldCreated: true}) // amc-agent has always been created by the installer (home <prefix>/agent)
		}
	}
	for _, m := range e.moves {
		e.r.line("MOVE   user %s -> %s (owner of %v; %s is removed after a successful start)", m.old, m.new, m.dirs, m.old)
	}
}

// moveOwners: step 2 part, data/ and agent/ (and the prober directory's group) to the new users.
func (e *eng) moveOwners() {
	for _, m := range e.moves {
		uid, gid, ok := e.lookupUser(m.new)
		if !ok && e.o.Apply {
			e.r.fail("user %s missing after useradd", m.new)
			continue
		}
		for _, d := range m.dirs {
			p := e.pre(d)
			if _, err := os.Stat(e.fs(p)); err != nil {
				continue
			}
			e.do(fmt.Sprintf("chown -R %s:%s %s", m.new, m.new, p), func() error { return e.chownTree(p, uid, gid, -1) })
		}
		if p := e.pre(probeDir); m.new == AgentUser {
			if _, err := os.Stat(e.fs(p)); err == nil {
				e.do(fmt.Sprintf("chgrp -R %s %s", m.new, p), func() error { return e.chownTree(p, -1, -1, gid) })
			}
		}
	}
}

// chownTree changes the owner of every file below p (symlinks themselves, not their targets). uid -1 = keep.
func (e *eng) chownTree(p string, uid, gid, onlyGid int) error {
	return filepath.WalkDir(e.fs(p), func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if onlyGid >= 0 {
			return e.o.Chown(path, -1, onlyGid)
		}
		return e.o.Chown(path, uid, gid)
	})
}

// markNewCreated: this run created the new user of a move (a rollback removes it again).
func (e *eng) markNewCreated(user string) {
	for _, m := range e.moves {
		if m.new == user {
			m.newCreated = true
		}
	}
}

// movedOld: the old name of a user this run moves ("" = none).
func (e *eng) movedOld(newUser string) string {
	for _, m := range e.moves {
		if m.new == newUser {
			return m.old
		}
	}
	return ""
}

// undoUserMoves (rollback): the old owners come back; a new user this run created loses its ACL entries and groups
// and is removed again.
func (e *eng) undoUserMoves() {
	for _, m := range e.moves {
		uid, gid, ok := e.lookupUser(m.old)
		if !ok {
			e.r.fail("rollback: user %s missing", m.old)
			continue
		}
		for _, d := range m.dirs {
			if err := e.chownTree(e.pre(d), uid, gid, -1); err != nil && !os.IsNotExist(err) {
				e.r.fail("rollback: chown %s: %v", d, err)
			}
		}
		if m.new == AgentUser {
			if err := e.chownTree(e.pre(probeDir), -1, -1, gid); err != nil && !os.IsNotExist(err) {
				e.r.fail("rollback: chgrp %s: %v", probeDir, err)
			}
		}
		if m.newCreated {
			e.dropUserAccess(m.new)
			if err := e.o.Runner.Run("userdel", m.new); err != nil {
				e.r.warn("rollback: userdel %s: %v", m.new, err)
			}
		}
		e.r.ok("rollback: %s owned by %s again", m.dirs, m.old)
	}
	if len(e.moves) > 0 {
		e.st.User = e.movedOld(e.o.User)
		if e.st.User == "" {
			e.st.User = e.o.User
		}
		e.st.Changed = true
	}
}

// finishUserMoves (after a successful start): the old users lose their ACL entries and group memberships and are
// removed (only users the installer created). Failures are warnings: monitoring already runs as the new users.
func (e *eng) finishUserMoves() {
	for _, m := range e.moves {
		e.dropUserAccess(m.old)
		if !m.oldCreated {
			e.r.warn("user %s was not created by this installer: kept (remove it yourself when nothing else uses it)", m.old)
			continue
		}
		if err := e.o.Runner.Run("userdel", m.old); err != nil {
			e.r.warn("userdel %s: %v", m.old, err)
			continue
		}
		e.r.ok("old user %s removed (replaced by %s)", m.old, m.new)
	}
}

// dropUserAccess removes user's entries from every recorded ACL path (deepest first) and from its extra groups.
func (e *eng) dropUserAccess(user string) {
	paths := append(append([]string{}, e.st.ACLFiles...), e.st.ACLDirs...)
	sort.Sort(sort.Reverse(sort.StringSlice(paths)))
	for _, p := range paths {
		if err := e.o.Runner.Run("setfacl", "-x", "u:"+user, p); err != nil {
			e.r.warn("setfacl -x u:%s %s: %v", user, p, err)
		}
	}
	var groups []string
	for g := range e.groupMembers(user) {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	for _, g := range groups {
		if err := e.o.Runner.Run("gpasswd", "-d", user, g); err != nil {
			e.r.warn("gpasswd -d %s %s: %v", user, g, err)
		}
	}
}

// legacyLeftovers: files of older layouts kept only for a rollback of the switch that replaced them (bin/otelcol-contrib
// and the helper data v0.19.0, bin/cloudprober + bin/amc.previous + the old polkit rule v0.20.0). Removed after a
// successful start, when no old unit is linked any more.
var legacyLeftovers = []string{"bin/otelcol-contrib", "bin/otelcol-contrib.previous", legacyProbeBinRel,
	legacyProbeBinRel + ".previous", legacyAgentBinRel + ".previous", "data/netconn", "data/kmsg", "data/procs", "data/sshd"}

func (e *eng) cleanupLegacy() {
	if len(e.legacyLinked()) > 0 {
		return
	}
	for _, rel := range legacyLeftovers {
		p := e.fs(e.pre(rel))
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		if err := os.RemoveAll(p); err != nil {
			e.r.warn("remove leftover %s: %v", rel, err)
			continue
		}
		e.r.ok("leftover of an older layout removed: %s", rel)
	}
	if err := os.Remove(e.fs(e.pre("netconn"))); err == nil { // only when empty
		e.r.ok("leftover of an older layout removed: netconn/")
	}
	if p := e.fs(LegacyPolkitRule) + ".previous"; fileExists(p) {
		if err := os.Remove(p); err == nil {
			e.r.ok("leftover of an older layout removed: %s.previous", LegacyPolkitRule)
		}
	}
}

func fileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// legacyReplacement names what replaced an old unit or file (for the plan / apply report).
func legacyReplacement(name string) string {
	if strings.Contains(name, "cloudprober") {
		return "monitoring-prober, v0.20.0"
	}
	return "monitoring-collector, v0.19.0"
}
