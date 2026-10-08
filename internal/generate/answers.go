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
	} `yaml:"checks,omitempty"`
}

// Service is one service's answers. Enabled nil = default (on when detected and amc has a profile).
type Service struct {
	Enabled *bool  `yaml:"enabled,omitempty"`
	Service string `yaml:"service,omitempty"` // oracle: service name (ORACLE_SERVICE), e.g. the PDB
	User    string `yaml:"user,omitempty"`    // oracle: monitoring user (ORACLE_MON_USER)
	// oracle (v0.4.0): service of the CDB root (ORACLE_CDB_SERVICE) for PDB states, role, limits, FRA; needs a
	// COMMON monitoring user (C##...). Empty or "-" = no CDB checks (non-CDB, or a local PDB user).
	CDBService string `yaml:"cdb_service,omitempty"`
	// tomcat: log files when the scan cannot find them (empty = what the scan found, "-" = none).
	AccessLog string   `yaml:"access_log,omitempty"` // access log glob, e.g. /opt/tomcat/logs/access_log.*.log
	Logs      []string `yaml:"logs,omitempty"`       // Tomcat log globs (catalina.out format), e.g. .../catalina.*.log
	// tomcat: zone of the times in Tomcat's own log (they have no offset); empty = the JVM's (scan), else the host's
	TimeZone string `yaml:"time_zone,omitempty"`
}

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
	for name, s := range a.Services {
		switch name {
		case "oracle", "tomcat", "redis", "caddy":
		default:
			return fmt.Errorf("services: unknown service %q (known: oracle, tomcat, redis, caddy)", name)
		}
		if name != "tomcat" && (s.AccessLog != "" || len(s.Logs) > 0 || s.TimeZone != "") {
			return fmt.Errorf("services.%s: access_log / logs / time_zone are Tomcat settings", name)
		}
		if name != "oracle" && s.CDBService != "" {
			return fmt.Errorf("services.%s: cdb_service is an Oracle setting", name)
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
