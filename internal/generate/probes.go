package generate

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Probes (v0.12.0): active checks run by Cloudprober (a second, small agent next to the collector) from this host:
// TCP connect, HTTP(S) GET and ICMP ping to other hosts or external APIs. Empty = Cloudprober is not installed.
// The local collector scrapes it (127.0.0.1:ProbePort) into the metrics pipeline:
//
//	cloudprober_total / _success / _failure / _timeouts   counters per probe and target
//	cloudprober_latency                                     cumulative MICROseconds of the successful probes
//	cloudprober_resp_code{code}, cloudprober_ssl_earliest_cert_expiry_sec   HTTP probes
//
// Labels: probe (tcp, ping, http_<name>), dst (host:port, host), target (the name below). Names are labels used by
// dashboards and alerts: keep them stable.
type Probes struct {
	IntervalS int         `yaml:"interval_s,omitempty" json:"interval_s"` // default 30 (10-3600)
	TCP       []TCPProbe  `yaml:"tcp,omitempty" json:"tcp"`
	HTTP      []HTTPProbe `yaml:"http,omitempty" json:"http"`
	Ping      []PingProbe `yaml:"ping,omitempty" json:"ping"`
}

type TCPProbe struct {
	Name string `yaml:"name" json:"name"`
	Host string `yaml:"host" json:"host"`
	Port int    `yaml:"port" json:"port"`
}

type HTTPProbe struct {
	Name string `yaml:"name" json:"name"`
	URL  string `yaml:"url" json:"url"`
}

type PingProbe struct {
	Name string `yaml:"name" json:"name"`
	Host string `yaml:"host" json:"host"`
}

// ProbePort is Cloudprober's own HTTP port (metrics), on 127.0.0.1 only.
const ProbePort = 9313

// ProbePrefix in the generated Cloudprober config is replaced by the engine with the install prefix.
const ProbePrefix = "@PREFIX@"

// ProbeDir (v0.13.0) holds Cloudprober's config and target files (below the prefix). Its own directory so that the
// agent (v0.13.0) may replace exactly these files and nothing else (v0.12.0 had them directly in config/).
const ProbeDir = "config/cloudprober"

// ProbeFiles is what Cloudprober needs: its config and the target files it re-reads (file name -> content).
type ProbeFiles struct {
	Config  []byte
	Targets map[string][]byte
	Ping    bool // ping probes need CAP_NET_RAW for the Cloudprober unit
}

var (
	probeNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	probeHostRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
)

// Empty: no probes = no Cloudprober.
func (p Probes) Empty() bool { return len(p.TCP)+len(p.HTTP)+len(p.Ping) == 0 }

func (p Probes) interval() int {
	if p.IntervalS == 0 {
		return 30
	}
	return p.IntervalS
}

func validProbeHost(h string) bool {
	return net.ParseIP(h) != nil || probeHostRE.MatchString(h)
}

func (p Probes) validate() error {
	if p.IntervalS != 0 && (p.IntervalS < 10 || p.IntervalS > 3600) {
		return fmt.Errorf("probes.interval_s: %d: use 10-3600", p.IntervalS)
	}
	seen := map[string]bool{}
	name := func(kind, n string) error {
		if !probeNameRE.MatchString(n) {
			return fmt.Errorf("probes.%s: name %q: a-z 0-9 _ (starts with a letter, max 63)", kind, n)
		}
		if seen[n] {
			return fmt.Errorf("probes: name %q twice (names are labels: one per probe)", n)
		}
		seen[n] = true
		return nil
	}
	tcp := map[string]bool{}
	for _, t := range p.TCP {
		if err := name("tcp", t.Name); err != nil {
			return err
		}
		if !validProbeHost(t.Host) {
			return fmt.Errorf("probes.tcp %s: host %q: a DNS name or an IP address", t.Name, t.Host)
		}
		if t.Port < 1 || t.Port > 65535 {
			return fmt.Errorf("probes.tcp %s: port %d: 1-65535", t.Name, t.Port)
		}
		k := t.Host + ":" + strconv.Itoa(t.Port)
		if tcp[k] {
			return fmt.Errorf("probes.tcp: %s twice", k)
		}
		tcp[k] = true
	}
	for _, h := range p.HTTP {
		if err := name("http", h.Name); err != nil {
			return err
		}
		u, err := url.Parse(h.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || !validProbeHost(u.Hostname()) {
			return fmt.Errorf("probes.http %s: %q is not an http(s) URL", h.Name, h.URL)
		}
		if u.User != nil {
			return fmt.Errorf("probes.http %s: %q contains credentials: not allowed (they would be printed and stored)", h.Name, u.Redacted())
		}
		if strings.ContainsAny(h.URL, "\"\\ \n") || u.Fragment != "" {
			return fmt.Errorf("probes.http %s: %q: no quotes, backslashes, spaces or #fragment", h.Name, h.URL)
		}
	}
	ping := map[string]bool{}
	for _, g := range p.Ping {
		if err := name("ping", g.Name); err != nil {
			return err
		}
		if !validProbeHost(g.Host) {
			return fmt.Errorf("probes.ping %s: host %q: a DNS name or an IP address", g.Name, g.Host)
		}
		if ping[g.Host] {
			return fmt.Errorf("probes.ping: %s twice", g.Host)
		}
		ping[g.Host] = true
	}
	return nil
}

// fileTarget is one entry of a Cloudprober file targets list (JSON). Name = the host (dialled or resolved),
// ip only for an IP literal; label "target" = our probe name.
type fileTarget struct {
	Name   string            `json:"name"`
	IP     string            `json:"ip,omitempty"`
	Port   int               `json:"port,omitempty"`
	Labels map[string]string `json:"labels"`
}

func targetsJSON(ts []fileTarget) []byte {
	b, _ := json.MarshalIndent(struct {
		Resource []fileTarget `json:"resource"`
	}{ts}, "", "  ")
	return append(b, '\n')
}

func ipOf(h string) string {
	if net.ParseIP(h) != nil {
		return h
	}
	return ""
}

// probeFiles builds the Cloudprober config (textproto) and its target files. TCP and ping use file targets: they
// are re-read every 30 s, so a later version can change the list without a restart (mesh).
func probeFiles(p Probes) *ProbeFiles {
	if p.Empty() {
		return nil
	}
	iv := p.interval()
	timeout := 5000
	if iv*1000 <= timeout {
		timeout = iv*1000 - 1000
	}
	pf := &ProbeFiles{Targets: map[string][]byte{}, Ping: len(p.Ping) > 0}
	var b strings.Builder
	b.WriteString("# config/cloudprober/cloudprober.cfg: generated by amc from the answers (probes) and the agent's list.\n")
	b.WriteString("# Do not edit: change the answers and run `amc plan`. Metrics on 127.0.0.1 only, scraped by the collector.\n")
	fmt.Fprintf(&b, "host: \"127.0.0.1\"\nport: %d\n\n", ProbePort)
	common := func(name, ptype string) {
		fmt.Fprintf(&b, "probe {\n  name: %q\n  type: %s\n", name, ptype)
	}
	tail := func() {
		fmt.Fprintf(&b, "  interval_msec: %d\n  timeout_msec: %d\n", iv*1000, timeout)
		b.WriteString("  additional_label { key: \"target\" value: \"@target.label.target@\" }\n}\n\n")
	}
	fileProbe := func(name, ptype, file, extra string) {
		common(name, ptype)
		fmt.Fprintf(&b, "  targets { file_targets { file_path: \"%s/%s/%s\" re_eval_sec: 30 } }\n", ProbePrefix, ProbeDir, file)
		b.WriteString("  targets_update_sec: 30\n" + extra)
		tail()
	}
	if len(p.TCP) > 0 {
		var ts []fileTarget
		for _, t := range p.TCP {
			ts = append(ts, fileTarget{Name: t.Host, IP: ipOf(t.Host), Port: t.Port, Labels: map[string]string{"target": t.Name}})
		}
		pf.Targets["cloudprober-tcp.json"] = targetsJSON(ts)
		fileProbe("tcp", "TCP", "cloudprober-tcp.json", "")
	}
	if len(p.Ping) > 0 {
		var ts []fileTarget
		for _, g := range p.Ping {
			ts = append(ts, fileTarget{Name: g.Host, IP: ipOf(g.Host), Labels: map[string]string{"target": g.Name}})
		}
		pf.Targets["cloudprober-ping.json"] = targetsJSON(ts)
		// raw socket + CAP_NET_RAW (the datagram socket would need net.ipv4.ping_group_range, a system setting)
		fileProbe("ping", "PING", "cloudprober-ping.json", "  ping_probe { use_datagram_socket: false }\n")
	}
	for _, h := range p.HTTP {
		u, _ := url.Parse(h.URL)
		port := u.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
		}
		rel := u.EscapedPath()
		if rel == "" {
			rel = "/"
		}
		if u.RawQuery != "" {
			rel += "?" + u.RawQuery
		}
		common("http_"+h.Name, "HTTP")
		fmt.Fprintf(&b, "  targets { endpoint { name: %q", u.Hostname())
		if ip := ipOf(u.Hostname()); ip != "" {
			fmt.Fprintf(&b, " ip: %q", ip)
		}
		fmt.Fprintf(&b, " labels { key: \"target\" value: %q } } }\n", h.Name)
		fmt.Fprintf(&b, "  http_probe {\n    protocol: %s\n    port: %s\n    relative_url: %q\n  }\n", strings.ToUpper(u.Scheme), port, rel)
		tail()
	}
	b.WriteString(probeSurfacer)
	pf.Config = []byte(b.String())
	return pf
}

const probeSurfacer = "surfacer {\n  type: PROMETHEUS\n  prometheus_surfacer { metrics_prefix: \"cloudprober_\" }\n}\n"

// emptyProbeFiles: Cloudprober without probes (an agent host before its first list): valid, serves only the surfacer.
func emptyProbeFiles() *ProbeFiles {
	cfg := "# config/cloudprober/cloudprober.cfg: generated by amc. No probes yet (the agent adds them).\n" +
		fmt.Sprintf("host: \"127.0.0.1\"\nport: %d\n\n", ProbePort) + probeSurfacer
	return &ProbeFiles{Targets: map[string][]byte{}, Config: []byte(cfg)}
}

// probeScrape: the collector scrapes Cloudprober; only the probe metrics are kept (not its own runtime / system
// metrics: the collector has those).
func probeScrape(p Probes) string {
	return fmt.Sprintf(`  # Cloudprober (probes in the answers): probe results per target. up = success / total over a window.
  prometheus/cloudprober:
    config:
      scrape_configs:
        - job_name: cloudprober
          scrape_interval: %ds
          static_configs:
            - targets: ["127.0.0.1:%d"]
          metric_relabel_configs:
            - source_labels: [__name__]
              regex: 'cloudprober_(total|success|failure|latency|timeouts|resp_code|ssl_earliest_cert_expiry_sec)'
              action: keep
`, p.interval(), ProbePort)
}
