// Package envfile reads KEY=VALUE files the way systemd's EnvironmentFile= does (the collector unit loads
// host.env and secrets/collector.env with it): one assignment per line, '#' / ';' comments, optional single
// or double quotes around the value, no variable expansion. Values may be secrets: this package never logs.
package envfile

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

var keyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Parse returns the assignments in file order (later duplicates win, as in systemd).
func Parse(b []byte) (map[string]string, error) {
	if bytes.Contains(b, []byte("\r")) {
		return nil, fmt.Errorf("Windows line endings (CR) are not allowed")
	}
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(strings.TrimPrefix(k, "export "))
		if !ok || !keyRE.MatchString(k) {
			return nil, fmt.Errorf("line %d: not KEY=VALUE", n) // never echo the line: it may hold a secret
		}
		v = strings.TrimSpace(v)
		// Quotes are removed; no escape sequences inside them (amc never writes any, see Format).
		if len(v) >= 2 && (v[0] == '\'' || v[0] == '"') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out, sc.Err()
}

// Missing returns the keys from want that are absent or empty.
func Missing(env map[string]string, want []string) []string {
	var m []string
	for _, k := range want {
		if env[k] == "" {
			m = append(m, k)
		}
	}
	return m
}

// Format writes KEY='value' lines (sorted by the caller). Values with ' or a newline are rejected, so the
// file means the same to systemd and to a POSIX shell.
func Format(keys []string, env map[string]string) ([]byte, error) {
	var b bytes.Buffer
	for _, k := range keys {
		v := env[k]
		if !keyRE.MatchString(k) {
			return nil, fmt.Errorf("invalid key %q", k)
		}
		if strings.ContainsAny(v, "'\n\r") {
			return nil, fmt.Errorf("value of %s contains a quote or a newline: not supported", k)
		}
		fmt.Fprintf(&b, "%s='%s'\n", k, v)
	}
	return b.Bytes(), nil
}
