// Package generate turns detection findings plus the operator's answers into the host part of the
// collector configuration: config/host.yaml (static receivers, full pipelines) and config/host.env (switches).
// Output is deterministic: the same input gives the same bytes.
package generate

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Answers is everything a scan cannot know (docs/design.md, section 9). No secrets in here.
type Answers struct {
	// Project groups hosts in reports and dashboards (resource attribute "project" on everything the host sends).
	Project  string             `yaml:"project,omitempty"`
	Services map[string]Service `yaml:"services,omitempty"`
	Checks   struct {
		HTTP []HTTPCheck `yaml:"http,omitempty"`
		// TCP (v0.11.0): connect checks from this host to OTHER hosts (host:port), e.g. the database or the next hop
		// of a request path. Metrics tcpcheck.status (1 = connected) and tcpcheck.duration (ms), attribute
		// tcpcheck.endpoint = the endpoint as written here. Loopback targets are refused: local services are checked by
		// their profiles, and the Oracle listener check stays the only 127.0.0.1 endpoint.
		TCP []TCPCheck `yaml:"tcp,omitempty"`
	} `yaml:"checks,omitempty"`
	// Probes (v0.12.0): Cloudprober probes from this host (tcp / http / ping), see probes.go. Empty = not installed.
	Probes Probes `yaml:"probes,omitempty"`
}

// Service is one service's answers. Enabled nil = default (on when detected and amc has a profile).
type Service struct {
	Enabled *bool  `yaml:"enabled,omitempty"`
	Service string `yaml:"service,omitempty"` // oracle: service name (ORACLE_SERVICE), e.g. the PDB
	User    string `yaml:"user,omitempty"`    // oracle: monitoring user (ORACLE_MON_USER)
	// oracle (v0.4.0): service of the CDB root (ORACLE_CDB_SERVICE) for PDB states, role, limits, FRA; needs a
	// COMMON monitoring user (C##...). Empty or "-" = no CDB checks (non-CDB, or a local PDB user).
	CDBService string `yaml:"cdb_service,omitempty"`
	// oracle (v0.8.0): true = a NON-CDB database: role, limits, FRA are read from the database itself
	// (ORACLE_NONCDB, sql_query/oracle_db) with the normal monitoring user. Not with cdb_service.
	NonCDB bool `yaml:"non_cdb,omitempty"`
	// tomcat: log files when the scan cannot find them (empty = what the scan found, "-" = none).
	AccessLog string   `yaml:"access_log,omitempty"` // access log glob, e.g. /opt/tomcat/logs/access_log.*.log
	Logs      []string `yaml:"logs,omitempty"`       // Tomcat log globs (catalina.out format), e.g. .../catalina.*.log
	// tomcat: zone of the times in Tomcat's own log (they have no offset); empty = the JVM's (scan), else the host's
	TimeZone string `yaml:"time_zone,omitempty"`
	// tomcat (v0.9.0): regular expression of the login request path (e.g. ^/app/login) -> metric tomcat.access.logins
	// (attribute status_class). Empty = no login metric. Needs the access log.
	LoginPath string `yaml:"login_path,omitempty"`
	// oracle (v0.9.0): Data Guard lag (V$DATAGUARD_STATS: apply / transport lag in seconds) -> oracle.dataguard.lag;
	// meaningful on the standby (the user must be able to log in there: Active Data Guard / read only).
	DataGuard bool `yaml:"data_guard,omitempty"`
	// oracle (v0.9.0): RMAN backups (V$RMAN_BACKUP_JOB_DETAILS) -> oracle.backup.age (hours since the last
	// COMPLETED job per input type) + oracle.backup.failed_24h. Grant V_$RMAN_BACKUP_JOB_DETAILS first.
	Backups bool `yaml:"backups,omitempty"`
}

// loginPathRE: a safe regular expression for an OTTL string (no quotes or backslashes).
var loginPathRE = regexp.MustCompile(`^[A-Za-z0-9^$/._*+?()|\[\]-]{1,200}$`)

// serviceRE: an Oracle service name (letters, digits, _ . -), e.g. orcl, ORCL.example.com. No $ (host.env).
var serviceRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,127}$`)

// zoneRE: an IANA zone name (Asia/Tashkent, Etc/GMT-5, UTC) or Local.
var zoneRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+/-]{0,63}$`)

// logPathRE: an absolute path / glob without spaces, quotes or control characters, or "-" (= none).
var logPathRE = regexp.MustCompile(`^(-|/[A-Za-z0-9_./*?\[\]{},+@%=:-]{1,255})$`)

// HTTPCheck is one up check. URLs are labels used by alerts and dashboards: keep them stable.
type HTTPCheck struct {
	URL     string `yaml:"url"`
	Comment string `yaml:"comment,omitempty"`
}

// TCPCheck is one connect check to another host. The endpoint is a label used by dashboards: keep it stable.
type TCPCheck struct {
	Endpoint string `yaml:"endpoint"`
	Comment  string `yaml:"comment,omitempty"`
}

// tcpEndpointRE: host:port with a DNS name or an IPv4 address, or [IPv6]:port. No scheme, no path.
var tcpEndpointRE = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9.-]{0,252}|\[[0-9A-Fa-f:.]{2,45}\]):([0-9]{1,5})$`)

// projectRE: empty (no project) or a plain name. No "," or "=": they separate OTEL_RESOURCE_ATTRIBUTES pairs.
var projectRE = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9 ._-]{0,63})?$`)

// LoadAnswers reads an answers file (unknown keys are an error: a typo must not be ignored silently).
func LoadAnswers(path string) (Answers, error) {
	var a Answers
	b, err := os.ReadFile(path)
	if err != nil {
		return a, err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&a); err != nil {
		return a, fmt.Errorf("%s: %w", path, err)
	}
	return a, a.Validate()
}

// Validate rejects unknown services, non-http(s) URLs and URLs with credentials.
func (a Answers) Validate() error {
	if !projectRE.MatchString(a.Project) {
		return fmt.Errorf("project: %q: use 1-64 characters A-Z a-z 0-9 space . _ - (it becomes a resource attribute)", a.Project)
	}
	for _, c := range a.Checks.HTTP {
		u, err := url.Parse(c.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("checks.http: %q is not an http(s) URL", c.URL)
		}
		if u.User != nil {
			return fmt.Errorf("checks.http: %q contains credentials: not allowed (they would be printed and stored)", u.Redacted())
		}
	}
	seen := map[string]bool{}
	for _, c := range a.Checks.TCP {
		m := tcpEndpointRE.FindStringSubmatch(c.Endpoint)
		if m == nil {
			return fmt.Errorf("checks.tcp: %q: use host:port (e.g. db.example.com:1521) or [IPv6]:port", c.Endpoint)
		}
		if p, _ := strconv.Atoi(m[2]); p < 1 || p > 65535 {
			return fmt.Errorf("checks.tcp: %q: port 1-65535", c.Endpoint)
		}
		h := strings.ToLower(strings.Trim(m[1], "[]"))
		if h == "localhost" || strings.HasPrefix(h, "127.") || h == "::1" || h == "0.0.0.0" || h == "::" {
			return fmt.Errorf("checks.tcp: %q: a loopback target; checks.tcp is for other hosts (local services are checked by their profiles)", c.Endpoint)
		}
		if seen[c.Endpoint] {
			return fmt.Errorf("checks.tcp: %q twice", c.Endpoint)
		}
		seen[c.Endpoint] = true
	}
	if err := a.Probes.validate(); err != nil {
		return err
	}
	for name, s := range a.Services {
		switch name {
		case "oracle", "tomcat", "redis", "caddy":
		default:
			return fmt.Errorf("services: unknown service %q (known: oracle, tomcat, redis, caddy)", name)
		}
		if name != "tomcat" && (s.AccessLog != "" || len(s.Logs) > 0 || s.TimeZone != "") {
			return fmt.Errorf("services.%s: access_log / logs / time_zone are Tomcat settings", name)
		}
		if name != "tomcat" && s.LoginPath != "" {
			return fmt.Errorf("services.%s: login_path is a Tomcat setting", name)
		}
		if s.LoginPath != "" {
			if !loginPathRE.MatchString(s.LoginPath) {
				return fmt.Errorf("services.tomcat.login_path %q: letters, digits and ^$/._*+?()|[]- only", s.LoginPath)
			}
			if _, err := regexp.Compile(s.LoginPath); err != nil {
				return fmt.Errorf("services.tomcat.login_path: %v", err)
			}
		}
		if name != "oracle" && (s.DataGuard || s.Backups) {
			return fmt.Errorf("services.%s: data_guard / backups are Oracle settings", name)
		}
		if name != "oracle" && s.CDBService != "" {
			return fmt.Errorf("services.%s: cdb_service is an Oracle setting", name)
		}
		if name != "oracle" && s.NonCDB {
			return fmt.Errorf("services.%s: non_cdb is an Oracle setting", name)
		}
		if s.NonCDB && s.CDBService != "" && s.CDBService != "-" {
			return fmt.Errorf("services.oracle: non_cdb and cdb_service exclude each other (a non-CDB has no CDB root)")
		}
		if s.NonCDB && strings.HasPrefix(strings.ToUpper(s.User), "C##") {
			return fmt.Errorf("services.oracle: non_cdb with a common user (%q): common users exist only in a CDB", s.User)
		}
		if s.CDBService != "" && s.CDBService != "-" && !serviceRE.MatchString(s.CDBService) {
			return fmt.Errorf("services.oracle.cdb_service: %q is not a service name", s.CDBService)
		}
		if s.CDBService != "" && s.CDBService != "-" && !strings.HasPrefix(strings.ToUpper(s.User), "C##") {
			return fmt.Errorf("services.oracle.cdb_service needs a common monitoring user (C##..., user: %q)", s.User)
		}
		if s.TimeZone != "" && !zoneRE.MatchString(s.TimeZone) {
			return fmt.Errorf("services.tomcat.time_zone: %q is not a zone name (e.g. Asia/Tashkent, UTC)", s.TimeZone)
		}
		for _, p := range append([]string{s.AccessLog}, s.Logs...) {
			if p != "" && !logPathRE.MatchString(p) {
				return fmt.Errorf("services.tomcat: log path %q: use an absolute path or glob without spaces, or '-'", p)
			}
		}
	}
	return nil
}

// Marshal writes the answers as YAML for <prefix>/answers.yaml (the defaults of the next run). No secrets.
func (a Answers) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2) // yaml.v3 defaults to 4
	if err := enc.Encode(a); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	b := buf.Bytes()
	head := "# amc answers: what a scan cannot know (no secrets). Written by amc; the next run uses them as defaults.\n"
	if string(b) == "{}\n" {
		b = nil
	}
	return append([]byte(head), b...), nil
}
