package generate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Agent settings from the control plane (v0.35.0, docs/design.md "Agent settings from the console"). The switches
// agent.<key>.allow below are root's (answers.yaml) and off by default; before this version somebody had to log in
// and edit the answers for each. Now the host owner writes ONCE which of them the console may switch:
//
//	agent:
//	  settings:
//	    allow: [disk_scan, rescan]
//
// Like the service switches, the control plane sends its COMPLETE set ("settings": {"revision", "set": {key: bool}})
// in the signed document, the agent checks it (CheckSettingsSet), root checks it again and writes SettingsFile, then
// runs the normal update (smoke run, automatic rollback). answers.yaml is never edited.
//
// Effective value of switch K (EffectiveAgent, the ONE place: plan / apply / update / scan / disk-scan / the agent
// / root's jobs all read the switches through it):
//   - pinned (answers.yaml writes agent.<K>.allow, whatever the value) = the answers' value (answers win);
//   - else K in agent.settings.allow and in the installed set = the set's value;
//   - else the default: off.

// SettingKeys: the only switches the control plane may set (a FIXED list, sorted). Each is agent.<key>.allow.
var SettingKeys = []string{"allow_edit", "disk_scan", "docker", "rescan", "services_edit"}

// SettingGroups (v0.36.0): consent keys for settings WITH VALUES; a group is one key and the console sends its
// COMPLETE value (SettingsValues): checks = checks.http[] + checks.tcp[]; oracle = services.oracle.{service, user,
// capacity, capacity_pdbs}; tomcat = services.tomcat.{logs, time_zone, login_path}. A FIXED list, sorted.
var SettingGroups = []string{"checks", "oracle", "tomcat"}

// ConsentKeys: every key answers.yaml agent.settings.allow may list (switches + groups + v0.37.0 passwords), sorted.
var ConsentKeys = func() []string {
	out := append(append(append([]string{}, SettingKeys...), SettingGroups...), PasswordKeys...)
	sort.Strings(out)
	return out
}()

// SettingsFile is the installed set (root 644, written by `monitoring-agent self-update`).
const SettingsFile = "config/settings.cp.yaml"

// AgentSettings is the host owner's consent list. Empty (default) = the control plane sets nothing on this host.
type AgentSettings struct {
	Allow []string `yaml:"allow,omitempty"`
}

func (s AgentSettings) validate() error {
	seen := map[string]bool{}
	for _, k := range s.Allow {
		if !slices.Contains(ConsentKeys, k) {
			return fmt.Errorf("agent.settings.allow: unknown key %q (known: %s)", k, strings.Join(ConsentKeys, ", "))
		}
		if seen[k] {
			return fmt.Errorf("agent.settings.allow: %q twice", k)
		}
		seen[k] = true
	}
	return nil
}

// Allows: k is in the consent list.
func (s AgentSettings) Allows(k string) bool { return slices.Contains(s.Allow, k) }

// ParseSettingsAllow reads a comma-separated consent list ("disk_scan,rescan"; "" or "none" = empty), sorted.
func ParseSettingsAllow(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "none" {
		return nil, nil
	}
	var out []string
	for _, k := range strings.Split(s, ",") {
		if k = strings.TrimSpace(k); k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	if err := (AgentSettings{Allow: out}).validate(); err != nil {
		return nil, err
	}
	return out, nil
}

// SettingsSet is the control plane's switches by key (a key missing = not managed by the control plane).
type SettingsSet map[string]bool

// SettingsOverlay is the set with its revision: the wire format ("settings" in the signed document), the file
// format and what the inventory reports (settings_cp).
type SettingsOverlay struct {
	Revision int64       `yaml:"revision" json:"revision"`
	Set      SettingsSet `yaml:"set" json:"set"`
	// Values (v0.36.0): the console's values of the groups (nil = none)
	Values *SettingsValues `yaml:"values,omitempty" json:"values,omitempty"`
	// Passwords (v0.37.0, the signed document only): {key: {id, sealed}}; a key missing = not managed (the env
	// value is left as it is). Never written to the file.
	Passwords map[string]SealedPassword `yaml:"-" json:"passwords,omitempty"`
	// PasswordIDs (v0.37.0, the file only): {key: id} of the passwords root wrote (never the blob, never the value)
	PasswordIDs map[string]string `yaml:"passwords,omitempty" json:"-"`
}

// Empty: nothing to install (no switch, no group, no password).
func (ov SettingsOverlay) Empty() bool {
	return len(ov.Set) == 0 && ov.Values.Groups() == nil && len(ov.Passwords) == 0 && len(ov.PasswordIDs) == 0
}

// passwordKeys: the password keys of the document or of the file, sorted.
func (ov SettingsOverlay) passwordKeys() []string {
	var out []string
	for k := range ov.Passwords {
		out = append(out, k)
	}
	for k := range ov.PasswordIDs {
		if _, ok := ov.Passwords[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// String: the switches and the groups (plan output).
func (ov SettingsOverlay) String() string {
	parts := []string{}
	if len(ov.Set) > 0 {
		parts = append(parts, ov.Set.String())
	}
	if g := ov.Values.Groups(); g != nil {
		parts = append(parts, "values of "+strings.Join(g, ", "))
	}
	if p := ov.passwordKeys(); p != nil {
		parts = append(parts, "passwords "+strings.Join(p, ", "))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "; ")
}

// Keys: the set's keys, sorted.
func (s SettingsSet) Keys() []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// String: "disk_scan on, rescan off" (plan output, sorted).
func (s SettingsSet) String() string {
	var parts []string
	for _, k := range s.Keys() {
		v := "off"
		if s[k] {
			v = "on"
		}
		parts = append(parts, k+" "+v)
	}
	return strings.Join(parts, ", ")
}

func (s SettingsSet) shape() error {
	for _, k := range s.Keys() {
		if !slices.Contains(SettingKeys, k) {
			return fmt.Errorf("unknown key %q (known: %s)", k, strings.Join(SettingKeys, ", "))
		}
	}
	return nil
}

// sw: the switch field of key k (nil = not a setting key).
func (ag *Agent) sw(k string) *bool {
	switch k {
	case "allow_edit":
		return &ag.AllowEdit.Allow
	case "disk_scan":
		return &ag.DiskScan.Allow
	case "docker":
		return &ag.Docker.Allow
	case "rescan":
		return &ag.Rescan.Allow
	case "services_edit":
		return &ag.ServicesEdit.Allow
	}
	return nil
}

// IsPinned: answers.yaml writes agent.<k>.allow (LoadAnswers records it). Answers built in code (no file read):
// a switch that is on counts as written.
func (ag *Agent) IsPinned(k string) bool {
	if ag.pinned != nil {
		return ag.pinned[k]
	}
	p := ag.sw(k)
	return p != nil && *p
}

// Pinned: the consent keys answers.yaml sets itself (sorted; never nil). v0.36.0: groups too, when the section
// knows them (loaded by LoadAnswers or an effective copy; answers built in code: switches only).
func (ag *Agent) Pinned() []string {
	out := []string{}
	for _, k := range ConsentKeys {
		if slices.Contains(SettingGroups, k) {
			if ag.pinned[k] {
				out = append(out, k)
			}
		} else if ag.IsPinned(k) {
			out = append(out, k)
		}
	}
	return out
}

// CheckSettingsSet: may the control plane install this set? ag = the answers' agent section. The WHOLE set is
// refused when a key is unknown, not in agent.settings.allow, or pinned in the answers. The agent and root both
// check it.
func CheckSettingsSet(s SettingsSet, ag *Agent) error {
	if ag == nil || len(ag.Settings.Allow) == 0 {
		return errors.New("settings from the control plane are off on this host (answers.yaml agent.settings.allow)")
	}
	if err := s.shape(); err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	for _, k := range s.Keys() {
		if !ag.Settings.Allows(k) {
			return fmt.Errorf("settings: %s is not in answers.yaml agent.settings.allow on this host", k)
		}
		if ag.IsPinned(k) {
			return fmt.Errorf("settings: %s is pinned on this host (answers.yaml agent.%s.allow): only the host owner switches it", k, k)
		}
	}
	return nil
}

// EffectiveAgent: the answers' agent section with the control plane's settings applied (the rule above). The
// caller's agent is not changed; the copy remembers which keys the answers pin.
func EffectiveAgent(ag Agent, s SettingsSet) Agent {
	pinned := map[string]bool{}
	for _, k := range SettingKeys {
		pinned[k] = ag.IsPinned(k)
	}
	for _, g := range SettingGroups { // v0.36.0: the group pins the section knows stay
		pinned[g] = ag.pinned[g]
	}
	out := ag
	out.pinned = pinned
	for _, k := range SettingKeys {
		v, ok := s[k]
		if !ok || pinned[k] || !ag.Settings.Allows(k) {
			continue
		}
		*out.sw(k) = v
	}
	return out
}

// LoadSettingsOverlay reads the installed set; missing = none (zero value, nil error). Strict.
func LoadSettingsOverlay(path string) (SettingsOverlay, error) {
	var ov SettingsOverlay
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
	for k, id := range ov.PasswordIDs { // v0.37.0
		if !slices.Contains(PasswordKeys, k) || !ValidPasswordID(id) {
			return ov, fmt.Errorf("%s: passwords: %q: unknown key or bad id", path, k)
		}
	}
	return ov, nil
}

// MarshalSettingsOverlay: the file with a header.
func MarshalSettingsOverlay(ov SettingsOverlay) ([]byte, error) {
	b, err := yaml.Marshal(ov)
	if err != nil {
		return nil, err
	}
	head := fmt.Sprintf("# The control plane's agent settings for this host (revision %d), written by\n"+
		"# `monitoring-agent self-update` within answers.yaml agent.settings.allow. Do not edit: the next change replaces it.\n", ov.Revision)
	return append([]byte(head), b...), nil
}

// LocalSettings: the installed set below prefix when answers.yaml agent.settings.allow is not empty ("" prefix or no
// consent = none).
func LocalSettings(ag *Agent, prefix string) (SettingsOverlay, error) {
	if ag == nil || len(ag.Settings.Allow) == 0 || prefix == "" {
		return SettingsOverlay{}, nil
	}
	return LoadSettingsOverlay(filepath.Join(prefix, filepath.FromSlash(SettingsFile)))
}

// EffectiveAnswers: a with the installed settings below prefix applied (ApplySettings: the switches of its agent
// section, v0.36.0 also the groups' values). The
// answers given are not changed (apply saves THEM as answers.yaml, never the effective copy). ov = the installed set
// as read (revision 0 = none).
func EffectiveAnswers(a Answers, prefix string) (Answers, SettingsOverlay, error) {
	if a.Agent == nil {
		return a, SettingsOverlay{}, nil
	}
	ov, err := LocalSettings(a.Agent, prefix)
	if err != nil {
		return a, ov, err
	}
	return ApplySettings(a, ov), ov, nil
}

// LoadEffectiveAnswers: <prefix>/answers.yaml with the installed settings applied (EffectiveAnswers).
func LoadEffectiveAnswers(prefix string) (Answers, error) {
	a, err := LoadAnswers(filepath.Join(prefix, "answers.yaml"))
	if err != nil {
		return a, err
	}
	eff, _, err := EffectiveAnswers(a, prefix)
	return eff, err
}

// ---- pinned keys survive a rewrite of answers.yaml

// pinnedIn: the setting keys whose agent.<key>.allow the YAML document writes (any value).
func pinnedIn(b []byte) map[string]bool {
	out := map[string]bool{}
	var doc struct {
		Agent map[string]yaml.Node `yaml:"agent"`
	}
	if yaml.Unmarshal(b, &doc) != nil {
		return out
	}
	for _, k := range SettingKeys {
		n, ok := doc.Agent[k]
		if !ok || n.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "allow" {
				out[k] = true
			}
		}
	}
	return out
}

// MarshalYAML: the agent section as written, plus "allow: false" for a key the answers pin to off (the struct's
// omitempty would drop it, and with it the pin, at the next apply).
func (ag Agent) MarshalYAML() (any, error) {
	type plain Agent
	var n yaml.Node
	if err := n.Encode(plain(ag)); err != nil {
		return nil, err
	}
	if n.Kind != yaml.MappingNode {
		return &n, nil
	}
	for _, k := range SettingKeys {
		if !ag.IsPinned(k) || *ag.sw(k) {
			continue
		}
		allowFalse := []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "allow"}, {Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false"}}
		found := false
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == k && n.Content[i+1].Kind == yaml.MappingNode {
				v := n.Content[i+1]
				v.Content = append(allowFalse, v.Content...)
				found = true
			}
		}
		if !found {
			n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k},
				&yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: allowFalse})
		}
	}
	return &n, nil
}
