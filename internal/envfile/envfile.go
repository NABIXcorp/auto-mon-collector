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
		// Quotes are removed; no escape sequences inside them (monitoring-agent never writes any, see Format).
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

// Set (v0.37.0) returns b with KEY='value': the first assignment of key is replaced in place, later ones are
// dropped, other lines (comments, other keys) stay as they are; no assignment = a new last line. The value is
// checked like Format; errors never hold it.
func Set(b []byte, key, value string) ([]byte, error) {
	if bytes.Contains(b, []byte("\r")) {
		return nil, fmt.Errorf("Windows line endings (CR) are not allowed")
	}
	line, err := Format([]string{key}, map[string]string{key: value})
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	done := false
	lines := strings.SplitAfter(string(b), "\n")
	for _, l := range lines {
		if l == "" {
			continue
		}
		t := strings.TrimSpace(l)
		k, _, ok := strings.Cut(t, "=")
		if ok && t[0] != '#' && t[0] != ';' && strings.TrimSpace(strings.TrimPrefix(k, "export ")) == key {
			if !done {
				out.Write(line)
				done = true
			}
			continue
		}
		out.WriteString(l)
		if !strings.HasSuffix(l, "\n") {
			out.WriteByte('\n')
		}
	}
	if !done {
		out.Write(line)
	}
	return out.Bytes(), nil
}
