package generate

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// The allowlist edited from the control plane (v0.26.0, docs/design.md section 17). The allowlist is the host
// owner's guard against a compromised control plane, so changing it from that control plane is off by default and
// bounded: the host owner switches it on in answers.yaml (agent.allow_edit) and sets the ceilings. The control plane
// sends its COMPLETE overlay (lists + numbers + ping) in the signed document; the agent checks it (CheckAllowOverlay),
// root checks it again and writes AllowOverlayFile. The effective allowlist = template + answers.yaml extras + the
// overlay (EffectiveAllow). The overlay can only add targets / ports and set the two numbers: it never touches the
// control-plane URL, its key, update or site.

// AgentAllowEdit is the host owner's switch and ceilings for the control plane's overlay. Default: off.
type AgentAllowEdit struct {
	Allow     bool `yaml:"allow,omitempty"`      // false (default) = every overlay is refused (and an installed one is ignored)
	Ping      bool `yaml:"ping,omitempty"`       // the overlay may switch ping on (the prober unit gets CAP_NET_RAW)
	MaxProbes int  `yaml:"max_probes,omitempty"` // ceiling for the overlay's max_probes; 0 = the value without the overlay
}

// AllowOverlayFile is the installed overlay (root 644, written by `monitoring-agent self-update`).
const AllowOverlayFile = "config/agent-allow.cp.yaml"

// Limits of an overlay.
const (
	OverlayMaxList     = 64
	overlayMaxProbes   = 100
	overlayMinInterval = 15
	overlayMinV4Prefix = 16
	overlayMinV6Prefix = 48
)

func (e AgentAllowEdit) validate() error {
	if e.MaxProbes < 0 || e.MaxProbes > overlayMaxProbes {
		return fmt.Errorf("agent.allow_edit.max_probes %d: 0-%d (0 = the value without the console's overlay)", e.MaxProbes, overlayMaxProbes)
	}
	return nil
}

// Ceiling: the highest max_probes the overlay may set, given the effective allowlist without it.
func (e AgentAllowEdit) Ceiling(base Allow) int {
	c := e.MaxProbes
	if c == 0 {
		c = base.MaxProbes
	}
	return min(c, overlayMaxProbes)
}

// Empty: an overlay without anything (= remove the installed one).
func (al Allow) Empty() bool {
	return len(al.Domains) == 0 && len(al.Networks) == 0 && len(al.Ports) == 0 && al.MaxProbes == 0 && al.MinIntervalS == 0 && !al.Ping
}

// overlayShape: the checks that do not depend on the host owner's switch and ceilings.
func (al Allow) overlayShape() error {
	switch {
	case len(al.Domains) > OverlayMaxList:
		return fmt.Errorf("%d domains, at most %d", len(al.Domains), OverlayMaxList)
	case len(al.Networks) > OverlayMaxList:
		return fmt.Errorf("%d networks, at most %d", len(al.Networks), OverlayMaxList)
	case len(al.Ports) > OverlayMaxList:
		return fmt.Errorf("%d ports, at most %d", len(al.Ports), OverlayMaxList)
	}
	for _, d := range al.Domains {
		if !domainRE.MatchString(d) {
			return fmt.Errorf("domain %q: lower-case DNS name or *.suffix", d)
		}
	}
	for _, n := range al.Networks {
		if err := overlayNetwork(n); err != nil {
			return err
		}
	}
	for _, p := range al.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("port %d: 1-65535", p)
		}
	}
	if al.MaxProbes < 0 || al.MaxProbes > overlayMaxProbes {
		return fmt.Errorf("max_probes %d: 0 or 1-%d", al.MaxProbes, overlayMaxProbes)
	}
	if al.MinIntervalS != 0 && al.MinIntervalS < overlayMinInterval {
		return fmt.Errorf("min_interval_s %d: 0 or at least %d", al.MinIntervalS, overlayMinInterval)
	}
	return nil
}

// overlayNetwork: a CIDR no wider than /16 (IPv4) or /48 (IPv6), never a default route. An IPv4-mapped IPv6 CIDR
// (::ffff:0:0/96) is an IPv4 network (the allowlist check matches IPv4 addresses against it) and gets the IPv4 bound.
func overlayNetwork(n string) error {
	ip, c, err := net.ParseCIDR(n)
	if err != nil {
		return fmt.Errorf("network %q: a CIDR (e.g. 192.0.2.0/24)", n)
	}
	ones, bits := c.Mask.Size()
	if ip.To4() != nil {
		if bits == 128 {
			ones -= 96
		}
		if ones < overlayMinV4Prefix {
			return fmt.Errorf("network %q: IPv4 at most /%d wide", n, overlayMinV4Prefix)
		}
		return nil
	}
	if ones < overlayMinV6Prefix {
		return fmt.Errorf("network %q: IPv6 at most /%d wide", n, overlayMinV6Prefix)
	}
	return nil
}

// CheckAllowOverlay: may the control plane install this overlay? edit = answers.yaml agent.allow_edit, base = the
// effective allowlist without any overlay (template + answers extras). The agent and root both check it.
func CheckAllowOverlay(ov Allow, edit AgentAllowEdit, base Allow) error {
	if !edit.Allow {
		return errors.New("allowlist changes from the control plane are off on this host (answers.yaml agent.allow_edit.allow)")
	}
	if err := ov.overlayShape(); err != nil {
		return fmt.Errorf("allowlist overlay: %w", err)
	}
	if c := edit.Ceiling(base); ov.MaxProbes > c {
		return fmt.Errorf("allowlist overlay: max_probes %d above this host's ceiling %d (answers.yaml agent.allow_edit.max_probes)", ov.MaxProbes, c)
	}
	if ov.Ping && !edit.Ping {
		return errors.New("allowlist overlay: ping may not be switched on from the control plane on this host (answers.yaml agent.allow_edit.ping)")
	}
	return nil
}

// EffectiveAllow: base (template + answers extras, defaults filled in) + the control plane's overlay: lists joined,
// a non-zero number of the overlay replaces (max_probes clamped to the ceiling), ping when either allows it (the
// overlay's only with agent.allow_edit.ping). Switched off (agent.allow_edit.allow false) = the overlay is ignored.
func EffectiveAllow(base Allow, edit AgentAllowEdit, ov Allow) Allow {
	if !edit.Allow || ov.Empty() {
		return base
	}
	out := base
	out.Domains = union(base.Domains, ov.Domains)
	out.Networks = union(base.Networks, ov.Networks)
	out.Ports = Allow{Ports: base.Ports}.Merge(Allow{Ports: ov.Ports}).Ports
	if ov.MaxProbes != 0 {
		out.MaxProbes = min(ov.MaxProbes, edit.Ceiling(base))
	}
	if ov.MinIntervalS != 0 {
		out.MinIntervalS = max(ov.MinIntervalS, overlayMinInterval)
	}
	out.Ping = base.Ping || (ov.Ping && edit.Ping)
	return out
}

// LoadAllowOverlay reads the installed overlay; missing = none (zero value, nil error). Strict like LoadAllow.
func LoadAllowOverlay(path string) (Allow, error) {
	var al Allow
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return al, nil
	}
	if err != nil {
		return al, err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&al); err != nil && err.Error() != "EOF" {
		return al, fmt.Errorf("%s: %w", path, err)
	}
	if err := al.overlayShape(); err != nil {
		return al, fmt.Errorf("%s: %w", path, err)
	}
	return al, nil
}

// MarshalAllowOverlay: the overlay file (the template's YAML format) with a header naming its revision.
func MarshalAllowOverlay(ov Allow, revision int64) ([]byte, error) {
	b, err := yaml.Marshal(ov)
	if err != nil {
		return nil, err
	}
	head := fmt.Sprintf("# The control plane's additions to this host's agent allowlist (revision %d), written by\n"+
		"# `monitoring-agent self-update` within answers.yaml agent.allow_edit. Do not edit: the next change replaces it.\n", revision)
	return append([]byte(head), b...), nil
}

// LocalAllow: the effective allowlist of an installation: the template (tmpl) + answers extras = base and, with the
// switch on, + the installed overlay below prefix ("" = none) = eff.
func LocalAllow(tmpl Allow, ag Agent, prefix string) (base, eff Allow, err error) {
	base = tmpl.Merge(ag.Allow)
	if prefix == "" {
		return base, base, nil
	}
	ov, err := LoadAllowOverlay(filepath.Join(prefix, filepath.FromSlash(AllowOverlayFile)))
	if err != nil {
		return base, base, err
	}
	return base, EffectiveAllow(base, ag.AllowEdit, ov), nil
}
