// Package hostdir turns a host part (host.yaml, host.env, optional site.d/*.yaml) into an engine.Desired.
// The host part comes from a directory (--host-dir) or from the generator (--answers); both use Build, so
// both paths install exactly the same way.
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

// Load reads dir: host.yaml and host.env are required, site.d/ is optional.
func Load(dir string) (engine.Desired, error) {
	hy, err := os.ReadFile(filepath.Join(dir, "host.yaml"))
	if err != nil {
		return engine.Desired{}, err
	}
	he, err := os.ReadFile(filepath.Join(dir, "host.env"))
	if err != nil {
		return engine.Desired{}, err
	}
	site, err := LoadSite(filepath.Join(dir, "site.d"))
	if err != nil {
		return engine.Desired{}, err
	}
	return Build(hy, he, site, "host-dir")
}

// LoadSite reads *.yaml / *.yml from dir ("" or a missing dir = no overlay).
func LoadSite(dir string) (map[string][]byte, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var site map[string][]byte
	for _, en := range entries {
		n := en.Name()
		if en.IsDir() || strings.HasPrefix(n, ".") || !(strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml")) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		if site == nil {
			site = map[string][]byte{}
		}
		site[n] = b
	}
	return site, nil
}

// Build derives what the engine needs from the host part. source goes into VERSION (host-dir / generated).
func Build(hostYAML, hostEnv []byte, site map[string][]byte, source string) (engine.Desired, error) {
	d := engine.Desired{HostYAML: hostYAML, HostEnv: hostEnv, Site: site}
	env, err := envfile.Parse(hostEnv)
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
	var names []string
	for n := range site {
		names = append(names, n)
	}
	sort.Strings(names)
	d.Version = []byte(fmt.Sprintf("installer=amc %s\ncommit=%s\ncollector=%s\nsource=%s\nsite.d=%s\n",
		version.Version, version.Commit, collector.Version, source, strings.Join(names, ",")))
	return d, nil
}
