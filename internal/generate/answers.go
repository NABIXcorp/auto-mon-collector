// Package generate turns detection findings plus the operator's answers into the host part of the
// collector configuration: config/host.yaml (static receivers, full pipelines) and config/host.env (switches).
// Output is deterministic: the same input gives the same bytes.
package generate

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Answers is everything a scan cannot know (docs/design.md, section 9). No secrets in here.
type Answers struct {
	Services map[string]Service `yaml:"services"`
	Checks   struct {
		HTTP []HTTPCheck `yaml:"http"`
	} `yaml:"checks"`
}

// Service is one service's answers. Enabled nil = default (on when detected and amc has a profile).
type Service struct {
	Enabled *bool  `yaml:"enabled"`
	Service string `yaml:"service"` // oracle: service name (ORACLE_SERVICE), e.g. the PDB
	User    string `yaml:"user"`    // oracle: monitoring user (ORACLE_MON_USER)
}

// HTTPCheck is one up check. URLs are labels used by alerts and dashboards: keep them stable.
type HTTPCheck struct {
	URL     string `yaml:"url"`
	Comment string `yaml:"comment"`
}

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
	return a, a.check()
}

func (a Answers) check() error {
	for _, c := range a.Checks.HTTP {
		u, err := url.Parse(c.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("checks.http: %q is not an http(s) URL", c.URL)
		}
		if u.User != nil {
			return fmt.Errorf("checks.http: %q contains credentials: not allowed (they would be printed and stored)", u.Redacted())
		}
	}
	for name := range a.Services {
		switch name {
		case "oracle", "tomcat", "redis", "caddy":
		default:
			return fmt.Errorf("services: unknown service %q (known: oracle, tomcat, redis, caddy)", name)
		}
	}
	return nil
}
