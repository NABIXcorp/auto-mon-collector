package generate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Agent settings WITH VALUES (v0.36.0, docs/design.md "Agent settings from the console"). Besides the switches the
// console may set three groups of answers, each one consent key (SettingGroups):
//
//	checks = checks.http[] + checks.tcp[]                          (both lists)
//	oracle = services.oracle.{service, user, capacity, capacity_pdbs}
//	tomcat = services.tomcat.{logs, time_zone, login_path}
//
// A group present in the set = the console's COMPLETE value of that group: it replaces the answers' fields of the
// group (empty lists / "" = none). A group missing = not managed (answers decide). Fields outside a group (oracle
// non_cdb, cdb_service, enabled, ...) always come from the answers. A group is PINNED (answers win, the console
// cannot set it) when answers.yaml writes any of its fields with a value: checks = any http or tcp check; oracle /
// tomcat = any of the group's fields not empty / not false. The effective answers (answers + values) must pass the
// normal answers validation, else the WHOLE set is refused (CheckSettings).

// ChecksValue is the group "checks".
type ChecksValue struct {
	HTTP []HTTPCheck `yaml:"http" json:"http"`
	TCP  []TCPCheck  `yaml:"tcp" json:"tcp"`
}

// OracleValue is the group "oracle".
type OracleValue struct {
	Service      string   `yaml:"service" json:"service"`
	User         string   `yaml:"user" json:"user"`
	Capacity     bool     `yaml:"capacity" json:"capacity"`
	CapacityPDBs []string `yaml:"capacity_pdbs" json:"capacity_pdbs"`
}

// TomcatValue is the group "tomcat".
type TomcatValue struct {
	Logs      []string `yaml:"logs" json:"logs"`
	TimeZone  string   `yaml:"time_zone" json:"time_zone"`
	LoginPath string   `yaml:"login_path" json:"login_path"`
}

// SettingsValues: the console's values by group (nil = the group is not managed by the console).
type SettingsValues struct {
	Checks *ChecksValue `yaml:"checks,omitempty" json:"checks,omitempty"`
	Oracle *OracleValue `yaml:"oracle,omitempty" json:"oracle,omitempty"`
	Tomcat *TomcatValue `yaml:"tomcat,omitempty" json:"tomcat,omitempty"`

	// bad: groups of the signed document this version does not know or cannot read (CheckSettings refuses the set;
	// the rest of the document goes on)
	bad []string
}

// UnmarshalJSON reads the groups strictly; an unknown or malformed group does not reject the whole document, it is
// remembered and refuses the settings set only (CheckSettings).
func (v *SettingsValues) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	*v = SettingsValues{}
	keys := slices.Sorted(maps.Keys(m))
	for _, g := range keys {
		var err error
		switch g {
		case "checks":
			v.Checks, err = decodeGroup[ChecksValue](m[g])
		case "oracle":
			v.Oracle, err = decodeGroup[OracleValue](m[g])
		case "tomcat":
			v.Tomcat, err = decodeGroup[TomcatValue](m[g])
		default:
			err = fmt.Errorf("unknown group (known: %s)", strings.Join(SettingGroups, ", "))
		}
		if err != nil {
			v.bad = append(v.bad, fmt.Sprintf("%s: %v", g, err))
		}
	}
	return nil
}

func decodeGroup[T any](raw json.RawMessage) (*T, error) {
	if string(bytes.TrimSpace(raw)) == "null" {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var t T
	if err := dec.Decode(&t); err != nil {
		return nil, err
	}
	return &t, nil
}

// Groups: the groups present, sorted (nil = none; a nil receiver = none).
func (v *SettingsValues) Groups() []string {
	if v == nil {
		return nil
	}
	var out []string
	if v.Checks != nil {
		out = append(out, "checks")
	}
	if v.Oracle != nil {
		out = append(out, "oracle")
	}
	if v.Tomcat != nil {
		out = append(out, "tomcat")
	}
	return out
}

// groupWritten: the answers write a field of group g with a value (= pinned).
func groupWritten(a Answers, g string) bool {
	switch g {
	case "checks":
		return len(a.Checks.HTTP)+len(a.Checks.TCP) > 0
	case "oracle":
		s := a.Services["oracle"]
		return s.Service != "" || s.User != "" || s.Capacity || len(s.CapacityPDBs) > 0
	case "tomcat":
		s := a.Services["tomcat"]
		return len(s.Logs) > 0 || s.TimeZone != "" || s.LoginPath != ""
	}
	return false
}

// settingPins: every consent key the answers pin (switches: agent.<key>.allow written; groups: groupWritten). An
// agent section that already knows its pins (loaded, or an effective copy) keeps them.
func settingPins(a Answers) map[string]bool {
	out := map[string]bool{}
	if a.Agent == nil {
		return out
	}
	for _, k := range SettingKeys {
		out[k] = a.Agent.IsPinned(k)
	}
	for _, g := range SettingGroups {
		if a.Agent.pinned != nil {
			out[g] = a.Agent.pinned[g]
		} else {
			out[g] = groupWritten(a, g)
		}
	}
	return out
}

// ApplySettings: a with the control plane's set applied: switches (EffectiveAgent) and the groups in
// agent.settings.allow that the answers do not pin. a is not changed (maps and lists are copied); the copy's agent
// section remembers the answers' pins.
func ApplySettings(a Answers, ov SettingsOverlay) Answers {
	if a.Agent == nil {
		return a
	}
	pins := settingPins(a)
	eff := EffectiveAgent(*a.Agent, ov.Set)
	eff.pinned = pins
	ag := a.Agent
	a.Agent = &eff
	v := ov.Values
	if v == nil {
		return a
	}
	use := func(g string) bool { return ag.Settings.Allows(g) && !pins[g] }
	if v.Checks != nil && use("checks") {
		a.Checks.HTTP = slices.Clone(v.Checks.HTTP)
		a.Checks.TCP = slices.Clone(v.Checks.TCP)
	}
	if (v.Oracle != nil && use("oracle")) || (v.Tomcat != nil && use("tomcat")) {
		svc := maps.Clone(a.Services)
		if svc == nil {
			svc = map[string]Service{}
		}
		if v.Oracle != nil && use("oracle") {
			s := svc["oracle"]
			s.Service, s.User, s.Capacity, s.CapacityPDBs = v.Oracle.Service, v.Oracle.User, v.Oracle.Capacity, slices.Clone(v.Oracle.CapacityPDBs)
			svc["oracle"] = s
		}
		if v.Tomcat != nil && use("tomcat") {
			s := svc["tomcat"]
			s.Logs, s.TimeZone, s.LoginPath = slices.Clone(v.Tomcat.Logs), v.Tomcat.TimeZone, v.Tomcat.LoginPath
			svc["tomcat"] = s
		}
		a.Services = svc
	}
	return a
}

// CheckSettings: may the control plane install this set? raw = the answers as written (not an effective copy).
// The WHOLE set is refused when a switch or group is unknown, not in agent.settings.allow or pinned, or when the
// effective answers (raw + the set) fail the normal answers validation. The agent and root both check it.
func CheckSettings(ov SettingsOverlay, raw Answers) error {
	if err := CheckSettingsSet(ov.Set, raw.Agent); err != nil {
		return err
	}
	// v0.37.0: passwords: known key, consented, an id, a blob of the right shape (root opens it: Open)
	for _, k := range ov.passwordKeys() {
		p, ok := ov.Passwords[k]
		switch {
		case !slices.Contains(PasswordKeys, k):
			return fmt.Errorf("settings: unknown password key %q (known: %s)", k, strings.Join(PasswordKeys, ", "))
		case !raw.Agent.Settings.Allows(k):
			return fmt.Errorf("settings: %s is not in answers.yaml agent.settings.allow on this host", k)
		case !ok:
			continue // the file's id only
		case !ValidPasswordID(p.ID):
			return fmt.Errorf("settings: %s: id must be 1..64 of A-Z a-z 0-9 _ -", k)
		}
		if err := checkSealedShape(p.Sealed); err != nil {
			return fmt.Errorf("settings: %s: %v", k, err)
		}
	}
	v := ov.Values
	if v == nil {
		return nil
	}
	if len(v.bad) > 0 {
		return fmt.Errorf("settings: values: %s", strings.Join(v.bad, "; "))
	}
	pins := settingPins(raw)
	for _, g := range v.Groups() {
		if !raw.Agent.Settings.Allows(g) {
			return fmt.Errorf("settings: %s is not in answers.yaml agent.settings.allow on this host", g)
		}
		if pins[g] {
			return fmt.Errorf("settings: %s is pinned on this host (answers.yaml writes %s): only the host owner changes it", g, groupFields[g])
		}
	}
	if err := ApplySettings(raw, ov).Validate(); err != nil {
		return fmt.Errorf("settings: the answers with these values are not valid: %w", err)
	}
	return nil
}

var groupFields = map[string]string{
	"checks": "checks.http / checks.tcp",
	"oracle": "services.oracle service / user / capacity / capacity_pdbs",
	"tomcat": "services.tomcat logs / time_zone / login_path",
}

// SettingsValuesOf: the values of the three groups in a (normally the effective answers), every group present and
// every list non-nil (the inventory's settings_values).
func SettingsValuesOf(a Answers) SettingsValues {
	nz := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return slices.Clone(s)
	}
	c := &ChecksValue{HTTP: slices.Clone(a.Checks.HTTP), TCP: slices.Clone(a.Checks.TCP)}
	if c.HTTP == nil {
		c.HTTP = []HTTPCheck{}
	}
	if c.TCP == nil {
		c.TCP = []TCPCheck{}
	}
	o, t := a.Services["oracle"], a.Services["tomcat"]
	return SettingsValues{Checks: c,
		Oracle: &OracleValue{Service: o.Service, User: o.User, Capacity: o.Capacity, CapacityPDBs: nz(o.CapacityPDBs)},
		Tomcat: &TomcatValue{Logs: nz(t.Logs), TimeZone: t.TimeZone, LoginPath: t.LoginPath}}
}
