package engine

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path"

	"github.com/NABIXcorp/auto-mon-collector/assets"
)

// The agent (v0.13.0): installed only when Desired.Agent is set. Its parts: user amc-agent (system, no shell; renamed
// in a later release), <prefix>/agent/ (key + state, 700), bin/monitoring-agent (a copy of this binary; v0.20.0, the
// old name bin/amc stays as a symlink to it), unit monitoring-agent, config/agent-allow.yaml (the project's
// allowlist template, optional), the polkit rule that lets it restart monitoring-prober, and write access to
// config/prober/ (group of the agent user, setgid) - nothing else. v0.16.0: the root oneshot unit monitoring-update
// (`monitoring-agent self-update`), linked but never enabled; the polkit rule lets the agent START it (a remote
// update, re-verified by root).

// AgentUser runs the agent (v0.21.0; before: LegacyAgentUser amc-agent, moved by an apply, see users.go).
const AgentUser = "monitoring-agent"

// PolkitRule: the only file the agent part writes outside the prefix (v0.20.0 name; LegacyPolkitRule before).
const (
	PolkitRule       = "/etc/polkit-1/rules.d/50-monitoring-agent.rules"
	LegacyPolkitRule = "/etc/polkit-1/rules.d/50-amc-agent.rules"
)

// agentBinRel is the agent binary below the prefix; legacyAgentBinRel (bin/amc, before v0.20.0) points to it.
const (
	agentBinRel       = "bin/monitoring-agent"
	legacyAgentBinRel = "bin/amc"
)

// Agent is what the agent part needs.
type Agent struct {
	AllowTemplate []byte // config/agent-allow.yaml (project template); nil = none
	Binary        string // the binary installed as bin/monitoring-agent (normally the running one)
}

const allowFile = "config/agent-allow.yaml"

// agentUserAndDirs: step 2 part for the agent and the prober directory owner.
func (e *eng) agentUserAndDirs() {
	if e.d.Agent != nil {
		if _, _, ok := e.lookupUser(AgentUser); ok {
			e.r.ok("user %s exists", AgentUser)
		} else if e.doCmd("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", e.pre("agent"),
			"--shell", e.nologin(), AgentUser) && e.o.Apply {
			e.st.AgentUserCreated, e.st.Changed = true, true
			e.markNewCreated(AgentUser)
		}
		uid, gid, _ := e.lookupUser(AgentUser)
		e.ensureDir(e.pre("agent"), 0o700, uid, gid)
	}
	if e.d.Probes == nil {
		return
	}
	// config/prober/: the agent replaces files here (group of the agent user, setgid); without agent root only
	if e.d.Agent != nil {
		_, gid, _ := e.lookupUser(AgentUser)
		e.ensureDir(e.pre(probeDir), os.ModeSetgid|0o775, 0, gid)
	} else {
		e.ensureDir(e.pre(probeDir), 0o755, 0, 0)
	}
}

// ensureDir: like dir, but also corrects mode / owner of an existing directory (the agent was switched on later).
func (e *eng) ensureDir(p string, mode os.FileMode, uid, gid int) {
	fi, err := os.Stat(e.fs(p))
	if err != nil {
		e.dir(p, mode, uid, gid)
		return
	}
	want := mode & (os.ModePerm | os.ModeSetgid)
	if fi.Mode()&(os.ModePerm|os.ModeSetgid) == want && ownedBy(fi, uid, gid) {
		e.r.ok("%s", p)
		return
	}
	e.do(fmt.Sprintf("chmod %o + chown %d:%d %s", modeBits(mode), uid, gid, p), func() error {
		if err := os.Chmod(e.fs(p), mode); err != nil {
			return err
		}
		return e.o.Chown(e.fs(p), uid, gid)
	})
}

func modeBits(m os.FileMode) uint32 {
	b := uint32(m.Perm())
	if m&os.ModeSetgid != 0 {
		b |= 0o2000
	}
	return b
}

// agentBinary: step 4c, bin/monitoring-agent = a copy of this binary (the agent unit runs it); bin/amc (the name
// before v0.20.0) becomes a symlink to it (an old regular bin/amc is kept as bin/amc.previous for a rollback).
func (e *eng) agentBinary() {
	if e.d.Agent == nil {
		return
	}
	e.r.step("4c. agent: binary + polkit rule")
	bin := e.pre(agentBinRel)
	want, err := os.ReadFile(e.d.Agent.Binary)
	if err != nil {
		e.r.fail("read the agent binary %s: %v", e.d.Agent.Binary, err)
		return
	}
	if have, err := os.ReadFile(e.fs(bin)); err == nil && sha256.Sum256(have) == sha256.Sum256(want) {
		e.r.ok("%s is this binary", bin)
	} else {
		e.r.changes++
		e.do("install "+bin+" (copy of this binary, mode 755, root)", func() error { return e.writeFile(bin, want, 0o755) })
	}
	old := e.pre(legacyAgentBinRel)
	if t, err := os.Readlink(e.fs(old)); err == nil && t == path.Base(agentBinRel) {
		e.r.ok("%s -> %s", old, path.Base(agentBinRel))
	} else {
		e.r.changes++
		e.do("link "+old+" -> "+path.Base(agentBinRel)+" (the name before v0.20.0)", func() error {
			if fi, err := os.Lstat(e.fs(old)); err == nil && fi.Mode().IsRegular() {
				if err := os.Rename(e.fs(old), e.fs(old+".previous")); err != nil {
					return err
				}
				e.agentBinMoved = true
			}
			tmp := e.fs(old) + ".link"
			os.Remove(tmp)
			if err := os.Symlink(path.Base(agentBinRel), tmp); err != nil {
				return err
			}
			return os.Rename(tmp, e.fs(old))
		})
	}
	if _, err := os.Lstat(e.fs(LegacyPolkitRule)); err == nil {
		e.r.changes++
		// kept as *.previous (polkit reads only *.rules) for a rollback, which links the old units again
		if e.do("remove "+LegacyPolkitRule+" (replaced by "+path.Base(PolkitRule)+")", func() error {
			if err := os.Rename(e.fs(LegacyPolkitRule), e.fs(LegacyPolkitRule)+".previous"); err != nil {
				return err
			}
			e.polkitMoved = true
			return nil
		}) && e.o.Apply {
			e.st.remove(&e.st.Polkit, LegacyPolkitRule)
		}
	}
	if _, err := os.Stat(e.fs(path.Dir(PolkitRule))); err != nil {
		e.r.warn("polkit not installed (%s missing): the agent cannot restart monitoring-prober; probe lists that change "+
			"its config wait for the next `monitoring-agent apply` (install polkit / polkitd)", path.Dir(PolkitRule))
		return
	}
	rule := assets.AgentPolkit()
	have, herr := os.ReadFile(e.fs(PolkitRule))
	if herr == nil && bytes.Equal(have, rule) {
		e.r.ok("%s", PolkitRule)
		e.st.add(&e.st.Polkit, PolkitRule)
		return
	}
	if herr == nil {
		e.prevPolkit = have // e.g. the rule for amc-agent (v0.20.0): a rollback writes it back
	}
	e.r.changes++
	if e.do("write "+PolkitRule+" (the agent may restart monitoring-prober and start monitoring-update, nothing else)",
		func() error { return e.writeFile(PolkitRule, rule, 0o644) }) && e.o.Apply {
		e.st.add(&e.st.Polkit, PolkitRule)
	}
}

// agentFiles: the agent's files below the prefix (step 5 diff).
func (e *eng) agentFiles(ud assets.UnitData) ([]file, error) {
	if e.d.Agent == nil {
		return nil, nil
	}
	b, err := assets.Unit(assets.AgentUnit, ud)
	if err != nil {
		return nil, err
	}
	u, err := assets.Unit(assets.UpdateUnit, ud)
	if err != nil {
		return nil, err
	}
	out := []file{{"systemd/" + assets.AgentUnit + ".service", b, 0o644}, {"systemd/" + assets.UpdateUnit + ".service", u, 0o644}}
	if t := e.d.Agent.AllowTemplate; t != nil {
		out = append(out, file{allowFile, t, 0o644})
	}
	return out, nil
}

// staleAgentFiles: agent files no longer wanted (agent removed, or the template removed).
func (e *eng) staleAgentFiles() []string {
	want := map[string]bool{}
	for _, f := range e.files {
		want[f.rel] = true
	}
	var out []string
	for _, rel := range []string{"systemd/" + assets.AgentUnit + ".service", "systemd/" + assets.UpdateUnit + ".service", allowFile} {
		if _, err := os.Stat(e.fs(e.pre(rel))); err == nil && !want[rel] {
			out = append(out, rel)
		}
	}
	return out
}

// dropAgent: agent removed from the answers -> stop + disable its unit (before its file goes) and remove the
// polkit rule. The key and state in <prefix>/agent stay until uninstall (enrol again = new key anyway).
func (e *eng) dropAgent() {
	if e.d.Agent != nil {
		return
	}
	e.dropUnit(assets.AgentUnit+".service", "no agent")
	e.unlinkUnit(assets.UpdateUnit+".service", "no agent")
	for _, p := range append([]string{}, e.st.Polkit...) {
		if err := os.Remove(e.fs(p)); err != nil && !os.IsNotExist(err) {
			e.r.fail("remove %s: %v", p, err)
			continue
		}
		e.st.remove(&e.st.Polkit, p)
		e.r.ok("no agent: %s removed", p)
	}
}

// unlinkUnit removes the link of a unit that is never enabled (monitoring-update) and forgets it.
func (e *eng) unlinkUnit(name, why string) {
	link := e.fs("/etc/systemd/system/" + name)
	if _, err := os.Lstat(link); err != nil {
		e.st.remove(&e.st.Units, name)
		return
	}
	if err := os.Remove(link); err != nil {
		e.r.fail("remove %s: %v", link, err)
		return
	}
	e.st.remove(&e.st.Units, name)
	e.r.ok("%s: %s unlinked", why, name)
}

// linkOnly: units linked into /etc/systemd/system but never enabled, (re)started or checked by apply: the agent
// starts monitoring-update itself (v0.16.0).
func (e *eng) linkOnly() []string {
	if e.d.Agent == nil {
		return nil
	}
	return []string{assets.UpdateUnit + ".service"}
}

// dropUnit stops, disables and unlinks a linked unit (it must still have its unit file: disable needs it).
func (e *eng) dropUnit(name, why string) {
	link := e.fs("/etc/systemd/system/" + name)
	if _, err := os.Lstat(link); err != nil {
		return
	}
	if err := e.o.Runner.Run("systemctl", "disable", "--now", name); err != nil {
		e.r.fail("systemctl disable --now %s: %v", name, err)
		return
	}
	if err := os.Remove(link); err != nil && !os.IsNotExist(err) {
		e.r.fail("remove %s: %v", link, err)
		return
	}
	e.st.remove(&e.st.Units, name)
	e.r.ok("%s: %s stopped, disabled and unlinked", why, name)
}
