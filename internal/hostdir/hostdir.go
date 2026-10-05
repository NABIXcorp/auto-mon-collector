// Package hostdir reads a host configuration directory (host.yaml, host.env, optional site.d/*.yaml) into
// an engine.Desired. Phase 2 input; from phase 3 the detector generates the same content.
//
// host.env switches that the engine needs:
//
//	ORACLE_MON=on        -> secret ORACLE_MON_PASSWORD required
//	ORACLE_ALERT_LOG=... -> read access (ACL) for that one file
//	TOMCAT_GROUP=...     -> collector user joins that group (Tomcat log directory)
package hostdir

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/NABIXcorp/auto-mon-collector/internal/collector"
	"github.com/NABIXcorp/auto-mon-collector/internal/engine"
	"github.com/NABIXcorp/auto-mon-collector/internal/envfile"
	"github.com/NABIXcorp/auto-mon-collector/internal/version"
)

// Load reads dir. host.yaml and host.env are required.
func Load(dir string) (engine.Desired, error) {
	var d engine.Desired
	var err error
	if d.HostYAML, err = os.ReadFile(filepath.Join(dir, "host.yaml")); err != nil {
		return d, err
	}
	if d.HostEnv, err = os.ReadFile(filepath.Join(dir, "host.env")); err != nil {
		return d, err
	}
	env, err := envfile.Parse(d.HostEnv)
	if err != nil {
		return d, fmt.Errorf("host.env: %w", err)
	}
	d.SecretKeys = []string{"OO_ENDPOINT", "OO_AUTH"}
	if env["ORACLE_MON"] == "on" {
		d.SecretKeys = append(d.SecretKeys, "ORACLE_MON_PASSWORD")
	}
	if p := env["ORACLE_ALERT_LOG"]; p != "" {
		d.ReadFiles = append(d.ReadFiles, p)
	}
	if g := env["TOMCAT_GROUP"]; g != "" {
		d.Groups = append(d.Groups, g)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "site.d"))
	if err != nil && !os.IsNotExist(err) {
		return d, err
	}
	for _, en := range entries {
		n := en.Name()
		if en.IsDir() || strings.HasPrefix(n, ".") || !(strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml")) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, "site.d", n))
		if err != nil {
			return d, err
		}
		if d.Site == nil {
			d.Site = map[string][]byte{}
		}
		d.Site[n] = b
	}
	var site []string
	for n := range d.Site {
		site = append(site, n)
	}
	sort.Strings(site)
	d.Version = []byte(fmt.Sprintf("installer=amc %s\ncommit=%s\ncollector=%s\nsource=%s\nsite.d=%s\n",
		version.Version, version.Commit, collector.Version, "host-dir", strings.Join(site, ",")))
	return d, nil
}
