package engine

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path"

	"github.com/NABIXcorp/auto-mon-collector/assets"
)

// The amc agent (v0.13.0): installed only when Desired.Agent is set. Its parts: user amc-agent (system, no
// shell), <prefix>/agent/ (key + state, amc-agent 700), bin/amc (a copy of this amc), unit monitoring-agent,
// config/agent-allow.yaml (the project's allowlist template, optional), the polkit rule that lets it restart
// Cloudprober, and write access to config/cloudprober/ (group amc-agent, setgid) - nothing else.

// AgentUser runs the agent.
const AgentUser = "amc-agent"

// PolkitRule: the only file the agent part writes outside the prefix.
const PolkitRule = "/etc/polkit-1/rules.d/50-amc-agent.rules"

// Agent is what the agent part needs.
type Agent struct {
	AllowTemplate []byte // config/agent-allow.yaml (project template); nil = none
	Binary        string // the amc binary installed as bin/amc (normally the running one)
}

const allowFile = "config/agent-allow.yaml"

// agentUserAndDirs: step 2 part for the agent and the Cloudprober directory owner.
func (e *eng) agentUserAndDirs() {
	if e.d.Agent != nil {
		if _, _, ok := e.lookupUser(AgentUser); ok {
			e.r.ok("user %s exists", AgentUser)
		} else if e.doCmd("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", e.pre("agent"),
			"--shell", e.nologin(), AgentUser) && e.o.Apply {
			e.st.AgentUserCreated, e.st.Changed = true, true
		}
		uid, gid, _ := e.lookupUser(AgentUser)
		e.ensureDir(e.pre("agent"), 0o700, uid, gid)
	}
	if e.d.Probes == nil {
		return
	}
	// config/cloudprober/: the agent replaces files here (group amc-agent, setgid); without agent root only
	if e.d.Agent != nil {
		_, gid, _ := e.lookupUser(AgentUser)
		e.ensureDir(e.pre("config/cloudprober"), os.ModeSetgid|0o775, 0, gid)
	} else {
		e.ensureDir(e.pre("config/cloudprober"), 0o755, 0, 0)
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

// agentBinary: step 4c, bin/amc = a copy of this amc (the agent unit runs it).
func (e *eng) agentBinary() {
	if e.d.Agent == nil {
		return
	}
	e.r.step("4c. agent: binary + polkit rule")
	bin := e.pre("bin/amc")
	want, err := os.ReadFile(e.d.Agent.Binary)
	if err != nil {
		e.r.fail("read the amc binary %s: %v", e.d.Agent.Binary, err)
		return
	}
	if have, err := os.ReadFile(e.fs(bin)); err == nil && sha256.Sum256(have) == sha256.Sum256(want) {
		e.r.ok("%s is this amc", bin)
	} else {
		e.r.changes++
		e.do("install "+bin+" (copy of this amc, mode 755, root)", func() error { return e.writeFile(bin, want, 0o755) })
	}
	if _, err := os.Stat(e.fs(path.Dir(PolkitRule))); err != nil {
		e.r.warn("polkit not installed (%s missing): the agent cannot restart Cloudprober; probe lists that change "+
			"Cloudprober's config wait for the next `amc apply` (install polkit / polkitd)", path.Dir(PolkitRule))
		return
	}
	rule := assets.AgentPolkit()
	if have, err := os.ReadFile(e.fs(PolkitRule)); err == nil && bytes.Equal(have, rule) {
		e.r.ok("%s", PolkitRule)
		e.st.add(&e.st.Polkit, PolkitRule)
		return
	}
	e.r.changes++
	if e.do("write "+PolkitRule+" (amc-agent may restart monitoring-cloudprober, nothing else)",
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
	out := []file{{"systemd/" + assets.AgentUnit + ".service", b, 0o644}}
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
	for _, rel := range []string{"systemd/" + assets.AgentUnit + ".service", allowFile} {
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
	for _, p := range append([]string{}, e.st.Polkit...) {
		if err := os.Remove(e.fs(p)); err != nil && !os.IsNotExist(err) {
			e.r.fail("remove %s: %v", p, err)
			continue
		}
		e.st.remove(&e.st.Polkit, p)
		e.r.ok("no agent: %s removed", p)
	}
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
