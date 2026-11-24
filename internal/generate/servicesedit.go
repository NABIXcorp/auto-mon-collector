package generate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Services switched on from the control plane (v0.33.0, docs/design.md "Switch a service on"). answers.yaml is root's
// and the console cannot change it; like the allowlist overlay, the control plane sends its COMPLETE set of switches
// in the signed document, the agent checks it (CheckServicesSet), root checks it again and writes ServicesFile. Only
// the kinds in CPServiceKinds (profiles that need no login and no new secret) can be switched; the host owner turns
// the whole feature on with answers.yaml agent.services_edit.allow (default off).
//
// Merge rule (EffectiveServices), answers win:
//   - services.<kind>.locked: true in answers.yaml = never by the control plane (a request naming it is refused);
//   - services.<kind>.enabled: true in answers.yaml = on anyway, with the answers' own port / path;
//   - absent, or enabled: false WITHOUT locked = the control plane's "on" switches it on with its port (/ path).
// enabled: false is today's "not decided yet" state on many hosts, so it alone does not lock a kind.

// AgentServicesEdit is the host owner's switch for the control plane's service switches. Default: off.
type AgentServicesEdit struct {
	Allow bool `yaml:"allow,omitempty"` // false (default) = every set is refused (and an installed one is ignored)
}

// ServicesFile is the installed set (root 644, written by `monitoring-agent self-update`).
const ServicesFile = "config/services.cp.yaml"

// CPServiceKinds: the only kinds the control plane may switch (a FIXED list: no login, no secret to add).
var CPServiceKinds = []string{"nginx", "redis"}

// DefaultNginxStatusPath: the stub_status location the console's steps add.
const DefaultNginxStatusPath = "/nginx_status"

// StatusPathRE: an nginx stub_status path (it goes into host.env and a URL).
var StatusPathRE = regexp.MustCompile(`^/[A-Za-z0-9_./-]{1,64}$`)

// ServiceSwitch is one kind in the set. On false = the control plane's switch is withdrawn (the answers decide).
type ServiceSwitch struct {
	On         bool   `yaml:"on" json:"on"`
	Port       int    `yaml:"port,omitempty" json:"port,omitempty"`
	StatusPath string `yaml:"status_path,omitempty" json:"status_path,omitempty"` // nginx only
}

// ServicesSet is the control plane's switches by kind.
type ServicesSet map[string]ServiceSwitch

// ServicesOverlay is the set with its revision: the wire format ("services" in the signed document), the file
// format and what the inventory reports (services_cp).
type ServicesOverlay struct {
	Revision int64       `yaml:"revision" json:"revision"`
	Set      ServicesSet `yaml:"set" json:"set"`
}

// Kinds: the set's kinds, sorted.
func (s ServicesSet) Kinds() []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Normalized: the default nginx status path filled in for a kind switched on.
func (s ServicesSet) Normalized() ServicesSet {
	out := ServicesSet{}
	for k, sw := range s {
		if k == "nginx" && sw.On && sw.StatusPath == "" {
			sw.StatusPath = DefaultNginxStatusPath
		}
		out[k] = sw
	}
	return out
}

// shape: the checks that do not depend on the host owner's answers.
func (s ServicesSet) shape() error {
	for _, k := range s.Kinds() {
		sw := s[k]
		if !slices.Contains(CPServiceKinds, k) {
			return fmt.Errorf("kind %q cannot be switched from the control plane (only %s)", k, strings.Join(CPServiceKinds, ", "))
		}
		if sw.Port < 0 || sw.Port > 65535 || (sw.On && sw.Port == 0) {
			return fmt.Errorf("%s: port %d: 1-65535", k, sw.Port)
		}
		if sw.StatusPath != "" && k != "nginx" {
			return fmt.Errorf("%s: status_path is an nginx setting", k)
		}
		if sw.StatusPath != "" && !StatusPathRE.MatchString(sw.StatusPath) {
			return fmt.Errorf("%s: status_path %q: /path of letters, digits and _ . / - (at most 64)", k, sw.StatusPath)
		}
	}
	return nil
}

// CheckServicesSet: may the control plane install this set? edit = answers.yaml agent.services_edit, ans = the
// answers' services (a locked kind may not be switched on). The agent and root both check it.
func CheckServicesSet(s ServicesSet, edit AgentServicesEdit, ans map[string]Service) error {
	if !edit.Allow {
		return errors.New("service switches from the control plane are off on this host (answers.yaml agent.services_edit.allow)")
	}
	if err := s.shape(); err != nil {
		return fmt.Errorf("services: %w", err)
	}
	for _, k := range s.Kinds() {
		if s[k].On && ans[k].Locked {
			return fmt.Errorf("services: %s is locked on this host (answers.yaml services.%s.locked): only the host owner switches it", k, k)
		}
	}
	return nil
}

// EffectiveServices: the answers' services with the control plane's switches merged in (the rule above). The
// answers map is not changed.
func EffectiveServices(ans map[string]Service, s ServicesSet) map[string]Service {
	if len(s) == 0 {
		return ans
	}
	out := make(map[string]Service, len(ans)+len(s))
	for k, v := range ans {
		out[k] = v
	}
	for _, k := range s.Kinds() {
		sw := s[k]
		a, ok := ans[k]
		if !sw.On || a.Locked || (ok && a.Enabled != nil && *a.Enabled) || !slices.Contains(CPServiceKinds, k) {
			continue
		}
		on := true
		a.Enabled, a.Port = &on, sw.Port
		if k == "nginx" {
			a.StatusPath = sw.StatusPath
		}
		out[k] = a
	}
	return out
}

// LoadServicesOverlay reads the installed set; missing = none (zero value, nil error). Strict.
func LoadServicesOverlay(path string) (ServicesOverlay, error) {
	var ov ServicesOverlay
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ov, nil
	}
	if err != nil {
		return ov, err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&ov); err != nil && err.Error() != "EOF" {
		return ov, fmt.Errorf("%s: %w", path, err)
	}
	if err := ov.Set.shape(); err != nil {
		return ov, fmt.Errorf("%s: %w", path, err)
	}
	return ov, nil
}

// MarshalServicesOverlay: the file with a header.
func MarshalServicesOverlay(ov ServicesOverlay) ([]byte, error) {
	b, err := yaml.Marshal(ov)
	if err != nil {
		return nil, err
	}
	head := fmt.Sprintf("# The control plane's service switches for this host (revision %d), written by\n"+
		"# `monitoring-agent self-update` within answers.yaml agent.services_edit. Do not edit: the next change replaces it.\n", ov.Revision)
	return append([]byte(head), b...), nil
}

// LocalServices: the installed set below prefix when answers.yaml agent.services_edit.allow is on ("" prefix or
// switched off = none).
func LocalServices(ag *Agent, prefix string) (ServicesOverlay, error) {
	if ag == nil || !ag.ServicesEdit.Allow || prefix == "" {
		return ServicesOverlay{}, nil
	}
	return LoadServicesOverlay(filepath.Join(prefix, filepath.FromSlash(ServicesFile)))
}

// String: "nginx on :80 /nginx_status, redis on :6380" (plan output, sorted).
func (s ServicesSet) String() string {
	var parts []string
	for _, k := range s.Kinds() {
		sw := s[k]
		if !sw.On {
			parts = append(parts, k+" off")
			continue
		}
		p := fmt.Sprintf("%s on :%d", k, sw.Port)
		if sw.StatusPath != "" {
			p += " " + sw.StatusPath
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, ", ")
}
