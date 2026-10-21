package generate

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Agent (v0.13.0): `amc agent` fetches a signed list of probes from a control plane and applies it to Cloudprober
// (docs/design.md, section 17). Only data comes from the control plane: no commands, no paths. The host owner
// decides here what may be probed at all (Allow); a probe outside it is rejected by the agent.
type Agent struct {
	URL             string `yaml:"url"`               // control plane base, e.g. https://agent.example.com/agent/
	ControlPlaneKey string `yaml:"control_plane_key"` // "ed25519:<base64>": the ONLY key that may sign probe lists
	Allow           Allow  `yaml:"allow,omitempty"`   // host extras, added to the project template (--agent-allow)
}

// Allow limits what the control plane may ask for. Template (--agent-allow FILE, installed as
// config/agent-allow.yaml) + the host's agent.allow = the effective list: lists are joined; a number set on the
// host replaces the template's; ping is allowed when either allows it.
type Allow struct {
	Domains      []string `yaml:"domains,omitempty"`        // exact names or "*.suffix" (any depth below)
	Networks     []string `yaml:"networks,omitempty"`       // CIDRs for IP targets; empty = no IP targets
	Ports        []int    `yaml:"ports,omitempty"`          // tcp ports and the ports of http(s) URLs
	MaxProbes    int      `yaml:"max_probes,omitempty"`     // default 30
	MinIntervalS int      `yaml:"min_interval_s,omitempty"` // default 15
	Ping         bool     `yaml:"ping,omitempty"`           // ping probes allowed (the Cloudprober unit gets CAP_NET_RAW)
}

const (
	defaultMaxProbes   = 30
	defaultMinInterval = 15
	// AllowFile is the installed project template.
	AllowFile = "config/agent-allow.yaml"
)

var domainRE = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// LoadAllow reads a template file (strict: unknown keys are errors).
func LoadAllow(path string) (Allow, error) {
	var al Allow
	b, err := os.ReadFile(path)
	if err != nil {
		return al, err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&al); err != nil && err.Error() != "EOF" {
		return al, fmt.Errorf("%s: %w", path, err)
	}
	if err := al.validate(); err != nil {
		return al, fmt.Errorf("%s: %w", path, err)
	}
	return al, nil
}

func (al Allow) validate() error {
	for _, d := range al.Domains {
		if !domainRE.MatchString(d) {
			return fmt.Errorf("agent allow: domain %q: lower-case DNS name or *.suffix", d)
		}
	}
	for _, n := range al.Networks {
		if _, _, err := net.ParseCIDR(n); err != nil {
			return fmt.Errorf("agent allow: network %q: a CIDR (e.g. 192.0.2.0/24)", n)
		}
	}
	for _, p := range al.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("agent allow: port %d: 1-65535", p)
		}
	}
	if al.MaxProbes < 0 || al.MaxProbes > 100 {
		return fmt.Errorf("agent allow: max_probes %d: 1-100", al.MaxProbes)
	}
	if al.MinIntervalS != 0 && (al.MinIntervalS < 10 || al.MinIntervalS > 3600) {
		return fmt.Errorf("agent allow: min_interval_s %d: 10-3600", al.MinIntervalS)
	}
	return nil
}

// Merge: template + host extras (see Allow). The result has the defaults filled in.
func (al Allow) Merge(host Allow) Allow {
	out := Allow{Ping: al.Ping || host.Ping, MaxProbes: al.MaxProbes, MinIntervalS: al.MinIntervalS}
	out.Domains = union(al.Domains, host.Domains)
	out.Networks = union(al.Networks, host.Networks)
	seen := map[int]bool{}
	for _, p := range append(append([]int{}, al.Ports...), host.Ports...) {
		if !seen[p] {
			seen[p] = true
			out.Ports = append(out.Ports, p)
		}
	}
	sort.Ints(out.Ports)
	if host.MaxProbes != 0 {
		out.MaxProbes = host.MaxProbes
	}
	if host.MinIntervalS != 0 {
		out.MinIntervalS = host.MinIntervalS
	}
	if out.MaxProbes == 0 {
		out.MaxProbes = defaultMaxProbes
	}
	if out.MinIntervalS == 0 {
		out.MinIntervalS = defaultMinInterval
	}
	return out
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// String is the effective allowlist in one line (printed by plan).
func (al Allow) String() string {
	or := func(xs []string) string {
		if len(xs) == 0 {
			return "-"
		}
		return strings.Join(xs, ",")
	}
	var ps []string
	for _, p := range al.Ports {
		ps = append(ps, strconv.Itoa(p))
	}
	return fmt.Sprintf("domains %s; networks %s; ports %s; max %d probes; interval >= %d s; ping %v",
		or(al.Domains), or(al.Networks), or(ps), al.MaxProbes, al.MinIntervalS, al.Ping)
}

func (a *Agent) validate() error {
	u, err := url.Parse(a.URL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("agent.url %q: https://host/path, no credentials / query", a.URL)
	}
	// http only to the loopback (tests, a local tunnel); everything else https
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return fmt.Errorf("agent.url %q: https only (http only for 127.0.0.1 / localhost)", a.URL)
	}
	if _, err := ParseKey(a.ControlPlaneKey); err != nil {
		return fmt.Errorf("agent.control_plane_key: %w", err)
	}
	return a.Allow.validate()
}

func isLoopback(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// ParseKey reads "ed25519:<standard base64 of 32 bytes>".
func ParseKey(s string) ([]byte, error) {
	const pre = "ed25519:"
	if !strings.HasPrefix(s, pre) {
		return nil, fmt.Errorf("%q: write it as ed25519:<base64>", s)
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, pre))
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("ed25519 public key: 32 bytes, standard base64")
	}
	return b, nil
}

// ---- probe sets from the control plane

// Validate applies the answers rules for probes (the same for a list from the control plane).
func (p Probes) Validate() error { return p.validate() }

// CheckAllow: every probe of p must be inside the effective allowlist. Nothing is resolved: IP literals must be in
// a network, names must match a domain; ports must be listed (http(s) URLs: the URL port or 80 / 443).
func (p Probes) CheckAllow(al Allow) error {
	n := len(p.TCP) + len(p.HTTP) + len(p.Ping)
	if n > al.MaxProbes {
		return fmt.Errorf("%d probes, allowed %d", n, al.MaxProbes)
	}
	if p.IntervalS != 0 && p.IntervalS < al.MinIntervalS {
		return fmt.Errorf("interval %d s below the allowed %d s", p.IntervalS, al.MinIntervalS)
	}
	port := func(name string, x int) error {
		for _, a := range al.Ports {
			if a == x {
				return nil
			}
		}
		return fmt.Errorf("%s: port %d not allowed", name, x)
	}
	for _, t := range p.TCP {
		if err := al.target(t.Name, t.Host); err != nil {
			return err
		}
		if err := port(t.Name, t.Port); err != nil {
			return err
		}
	}
	for _, h := range p.HTTP {
		u, err := url.Parse(h.URL)
		if err != nil {
			return fmt.Errorf("%s: bad URL", h.Name)
		}
		if err := al.target(h.Name, u.Hostname()); err != nil {
			return err
		}
		x := map[string]int{"http": 80, "https": 443}[u.Scheme]
		if u.Port() != "" {
			x, _ = strconv.Atoi(u.Port())
		}
		if err := port(h.Name, x); err != nil {
			return err
		}
	}
	if len(p.Ping) > 0 && !al.Ping {
		return fmt.Errorf("ping probes not allowed on this host")
	}
	for _, g := range p.Ping {
		if err := al.target(g.Name, g.Host); err != nil {
			return err
		}
	}
	return nil
}

func (al Allow) target(name, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		for _, n := range al.Networks {
			if _, c, err := net.ParseCIDR(n); err == nil && c.Contains(ip) {
				return nil
			}
		}
		return fmt.Errorf("%s: address %s not in the allowed networks", name, host)
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range al.Domains {
		if strings.HasPrefix(d, "*.") {
			if strings.HasSuffix(h, d[1:]) && len(h) > len(d)-1 {
				return nil
			}
		} else if h == d {
			return nil
		}
	}
	return fmt.Errorf("%s: host %s not in the allowed domains", name, host)
}

// MergeProbes: the answers' own probes + the control plane's (one Cloudprober config). The shorter interval wins.
// Names must stay unique (checked by Validate on the result).
func MergeProbes(local, remote Probes) Probes {
	out := Probes{IntervalS: local.IntervalS,
		TCP:  append(append([]TCPProbe{}, local.TCP...), remote.TCP...),
		HTTP: append(append([]HTTPProbe{}, local.HTTP...), remote.HTTP...),
		Ping: append(append([]PingProbe{}, local.Ping...), remote.Ping...)}
	if remote.IntervalS != 0 && (out.IntervalS == 0 || remote.IntervalS < out.IntervalS) {
		out.IntervalS = remote.IntervalS
	}
	return out
}

// ProbeFilesFor builds the Cloudprober files for a probe set. empty=true gives a config without probes (the agent
// keeps Cloudprober running, so a later list starts at once).
func ProbeFilesFor(p Probes, empty bool) *ProbeFiles {
	if p.Empty() && empty {
		return emptyProbeFiles()
	}
	return probeFiles(p)
}
