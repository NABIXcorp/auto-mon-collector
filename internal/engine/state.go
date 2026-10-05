package engine

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
)

// StateFile (<prefix>/amc-state.json) lists what amc changed OUTSIDE its own directory, so `amc uninstall`
// removes exactly that and nothing else. No secrets: paths and names only.
const StateFile = "amc-state.json"

type state struct {
	Version     int      `json:"version"`
	Prefix      string   `json:"prefix"`
	User        string   `json:"user"`
	UserCreated bool     `json:"user_created"`     // amc created the collector user (or adopted ours)
	ACLFiles    []string `json:"acl_files"`        // setfacl u:<user>:r
	ACLDirs     []string `json:"acl_dirs"`         // setfacl u:<user>:--x (traverse)
	Groups      []string `json:"groups_added"`     // usermod -aG
	FContexts   []string `json:"selinux_fcontext"` // semanage fcontext -a -t bin_t
	Units       []string `json:"units"`            // linked into /etc/systemd/system
	Changed     bool     `json:"-"`
}

func (e *eng) statePath() string { return e.fs(e.pre(StateFile)) }

// loadState reads the state file; a missing file is an empty state (fresh host or pre-amc install).
func (e *eng) loadState() (*state, bool) {
	s := &state{Version: 1, Prefix: e.o.Prefix, User: e.o.User}
	b, err := os.ReadFile(e.statePath())
	if err != nil {
		return s, false
	}
	if json.Unmarshal(b, s) != nil {
		return &state{Version: 1, Prefix: e.o.Prefix, User: e.o.User}, false
	}
	return s, true
}

func (s *state) add(list *[]string, v string) {
	for _, x := range *list {
		if x == v {
			return
		}
	}
	*list = append(*list, v)
	sort.Strings(*list)
	s.Changed = true
}

// saveState writes the state (apply mode only, root 644).
func (e *eng) saveState() error {
	if e.st == nil || !e.st.Changed {
		return nil
	}
	b, err := json.MarshalIndent(e.st, "", "  ")
	if err != nil {
		return err
	}
	return e.writeFile(e.pre(StateFile), append(b, '\n'), 0o644)
}

// hasUserACL reports whether getfacl shows an entry for the collector user on p (read-only check, used to
// adopt ACLs that an earlier installer set).
func (e *eng) hasUserACL(p string) bool {
	out, err := e.o.Runner.Output(nil, "getfacl", "-p", "--omit-header", p)
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "user:"+e.o.User+":") {
			return true
		}
	}
	return false
}
