package generate

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Collector overlays from the control plane (v0.23.0, docs/design.md section 17). A control plane that could send
// ANY collector configuration could read any file on the host (a file_log include), run commands or send all data
// to another address (an exporter endpoint). So it may send only overlays inside a fixed catalog: processors of the
// types below, and the processor lists of existing pipelines. No receivers, exporters, extensions, connectors,
// telemetry settings, no ${...} expansion (that reads files / env), no YAML anchors or tags. The agent checks this
// before the hand-off and root checks it again (it does not trust the agent); the collector's own validate and the
// smoke run follow.

// AgentSite is the host owner's switch for overlays from the control plane. Default: off.
type AgentSite struct {
	Allow bool `yaml:"allow,omitempty"` // false (default) = every overlay request is refused
}

// SitePrefix: the control plane's overlays are installed as config/site.d/<SitePrefix><name>. Files without it
// (from --site-dir) are the host owner's and are kept; the control plane replaces only its own set.
const SitePrefix = "cp-"

// Limits of one overlay set.
const (
	SiteMaxFiles = 16
	SiteMaxFile  = 64 << 10
	SiteMaxTotal = 128 << 10
)

// SiteCatalog: the processor types an overlay may define (compiled into our collector, collector/builder-config.yaml).
var SiteCatalog = []string{"filter", "transform", "tail_sampling"}

var siteNameRE = regexp.MustCompile(`^cp-[0-9a-z][0-9a-z_.-]{0,58}\.yaml$`)

// CheckSite checks a whole overlay set from the control plane (file name -> YAML).
func CheckSite(files map[string]string) error {
	if len(files) > SiteMaxFiles {
		return fmt.Errorf("overlays: %d files, at most %d", len(files), SiteMaxFiles)
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	total := 0
	for _, n := range names {
		if !siteNameRE.MatchString(n) || strings.Contains(n, "..") {
			return fmt.Errorf("overlay name %q: %s<a-z 0-9 _ . ->.yaml", n, SitePrefix)
		}
		total += len(files[n])
		if len(files[n]) > SiteMaxFile {
			return fmt.Errorf("overlay %s: %d bytes, at most %d", n, len(files[n]), SiteMaxFile)
		}
		if err := CheckOverlay([]byte(files[n])); err != nil {
			return fmt.Errorf("overlay %s: %w", n, err)
		}
	}
	if total > SiteMaxTotal {
		return fmt.Errorf("overlays: %d bytes, at most %d", total, SiteMaxTotal)
	}
	return nil
}

// CheckOverlay checks one overlay file against the catalog.
func CheckOverlay(b []byte) error {
	// a literal $ is written $$ in collector configuration; any other $ starts an expansion (${env:..}, ${file:..})
	if strings.Contains(strings.ReplaceAll(string(b), "$$", ""), "$") {
		return errors.New("a $ that is not $$: ${...} expansion (env, files) is not allowed in overlays")
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("YAML: %v", err)
	}
	var more yaml.Node
	if err := dec.Decode(&more); err == nil {
		return errors.New("one YAML document only")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return errors.New("empty")
	}
	if err := plainTree(doc.Content[0]); err != nil {
		return err
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return errors.New("the top level must be a mapping")
	}
	for i := 0; i < len(root.Content); i += 2 {
		k, v := root.Content[i].Value, root.Content[i+1]
		switch k {
		case "processors":
			if err := checkProcessors(v); err != nil {
				return err
			}
		case "service":
			if err := checkService(v); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%q is not allowed (only processors and service.pipelines.<name>.processors)", k)
		}
	}
	return nil
}

// plainTree: no anchors, aliases, merge keys or explicit tags anywhere.
func plainTree(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return errors.New("YAML anchors / aliases are not allowed")
	}
	if n.Style&yaml.TaggedStyle != 0 {
		return fmt.Errorf("YAML tag %s is not allowed", n.Tag)
	}
	if n.Kind == yaml.ScalarNode && n.Tag == "!!merge" {
		return errors.New("YAML merge keys (<<) are not allowed")
	}
	for _, c := range n.Content {
		if err := plainTree(c); err != nil {
			return err
		}
	}
	return nil
}

func checkProcessors(v *yaml.Node) error {
	if v.Kind != yaml.MappingNode {
		return errors.New("processors: must be a mapping")
	}
	for i := 0; i < len(v.Content); i += 2 {
		id := v.Content[i].Value
		typ, _, _ := strings.Cut(id, "/")
		ok := false
		for _, c := range SiteCatalog {
			ok = ok || typ == c
		}
		if !ok {
			return fmt.Errorf("processor %q: type %q is not in the overlay catalog (%s)", id, typ, strings.Join(SiteCatalog, ", "))
		}
		if v.Content[i+1].Kind != yaml.MappingNode {
			return fmt.Errorf("processor %q: settings must be a mapping", id)
		}
	}
	return nil
}

func checkService(v *yaml.Node) error {
	if v.Kind != yaml.MappingNode {
		return errors.New("service: must be a mapping")
	}
	for i := 0; i < len(v.Content); i += 2 {
		if v.Content[i].Value != "pipelines" {
			return fmt.Errorf("service.%s is not allowed (only service.pipelines.<name>.processors)", v.Content[i].Value)
		}
		ps := v.Content[i+1]
		if ps.Kind != yaml.MappingNode {
			return errors.New("service.pipelines: must be a mapping")
		}
		for j := 0; j < len(ps.Content); j += 2 {
			name, p := ps.Content[j].Value, ps.Content[j+1]
			if p.Kind != yaml.MappingNode {
				return fmt.Errorf("service.pipelines.%s: must be a mapping", name)
			}
			for k := 0; k < len(p.Content); k += 2 {
				if p.Content[k].Value != "processors" {
					return fmt.Errorf("service.pipelines.%s.%s is not allowed (only processors)", name, p.Content[k].Value)
				}
				l := p.Content[k+1]
				if l.Kind != yaml.SequenceNode {
					return fmt.Errorf("service.pipelines.%s.processors: must be a list", name)
				}
				for _, it := range l.Content {
					if it.Kind != yaml.ScalarNode {
						return fmt.Errorf("service.pipelines.%s.processors: names only", name)
					}
				}
			}
		}
	}
	return nil
}
