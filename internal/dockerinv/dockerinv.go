// Package dockerinv (v0.34.0) reads the names and states of Docker containers from the engine's own state files
// (<root>/containers/<id>/config.v2.json), as root, WITHOUT the Docker socket and without the docker CLI (the socket
// is root on the host). It copies a short allowlist of fields: no environment, no command line, no mounts, no labels
// other than the three compose ones. Opt-in: answers.yaml agent.docker.allow.
package dockerinv

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// DefaultRoot is where the Docker engine keeps its state on Linux.
const DefaultRoot = "/var/lib/docker"

const (
	// MaxContainers caps the list (sorted by name, the first ones are kept).
	MaxContainers = 300
	maxString     = 200
	maxConfigFile = 4 << 20 // a config.v2.json larger than this is skipped (it holds the whole environment)
)

// Container is one container as the inventory carries it.
type Container struct {
	ID         string `json:"id"` // 64 hex
	Name       string `json:"name"`
	Image      string `json:"image"`
	Project    string `json:"project"`     // label com.docker.compose.project ("" = not a compose container)
	Service    string `json:"service"`     // label com.docker.compose.service
	WorkingDir string `json:"working_dir"` // label com.docker.compose.project.working_dir
	// State: running | exited | restarting | paused | created | dead
	State      string `json:"state"`
	ExitCode   int    `json:"exit_code"`
	Health     string `json:"health"` // healthy | unhealthy | starting | "" (no health check)
	Restarts   int    `json:"restarts"`
	StartedAt  int64  `json:"started_at"`  // unix seconds, 0 = never started
	FinishedAt int64  `json:"finished_at"` // unix seconds, 0 = running or never finished
}

// Inventory is the `docker` section of inventory.json.
type Inventory struct {
	At         int64       `json:"at"` // unix seconds, when the scan read it
	Containers []Container `json:"containers"`
}

var idRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidID: the full 64-hex container id.
func ValidID(s string) bool { return idRE.MatchString(s) }

// configV2 is the subset of config.v2.json that is read; everything else in the file is ignored by the decoder.
type configV2 struct {
	ID     string `json:"ID"`
	Name   string `json:"Name"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Running    bool   `json:"Running"`
		Paused     bool   `json:"Paused"`
		Restarting bool   `json:"Restarting"`
		Dead       bool   `json:"Dead"`
		ExitCode   int    `json:"ExitCode"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
		Health     *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	RestartCount int `json:"RestartCount"`
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxString {
		return s
	}
	s = s[:maxString]
	for !utf8.ValidString(s) { // do not cut a character in half
		s = s[:len(s)-1]
	}
	return strings.TrimSpace(s)
}

func unixOf(s string) int64 {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() <= 1 { // Docker writes 0001-01-01T00:00:00Z for "never"
		return 0
	}
	return t.Unix()
}

// parse reads one config.v2.json. dirID is the folder name (the id when the file does not say).
func parse(b []byte, dirID string) (Container, bool) {
	var c configV2
	if err := json.Unmarshal(b, &c); err != nil {
		return Container{}, false
	}
	id := c.ID
	if !ValidID(id) {
		id = dirID
	}
	if !ValidID(id) {
		return Container{}, false
	}
	out := Container{
		ID:         id,
		Name:       clip(strings.TrimPrefix(strings.TrimSpace(c.Name), "/")),
		Image:      clip(c.Config.Image),
		Project:    clip(c.Config.Labels["com.docker.compose.project"]),
		Service:    clip(c.Config.Labels["com.docker.compose.service"]),
		WorkingDir: clip(c.Config.Labels["com.docker.compose.project.working_dir"]),
		ExitCode:   c.State.ExitCode,
		Restarts:   c.RestartCount,
		StartedAt:  unixOf(c.State.StartedAt),
		FinishedAt: unixOf(c.State.FinishedAt),
	}
	if c.State.Health != nil {
		switch h := c.State.Health.Status; h {
		case "healthy", "unhealthy", "starting":
			out.Health = h
		}
	}
	// the order Docker itself uses for its status word
	switch s := c.State; {
	case s.Paused:
		out.State = "paused"
	case s.Restarting:
		out.State = "restarting"
	case s.Running:
		out.State = "running"
	case s.Dead:
		out.State = "dead"
	case out.StartedAt == 0:
		out.State = "created"
	default:
		out.State = "exited"
	}
	if out.State == "running" || out.State == "paused" || out.State == "restarting" {
		out.FinishedAt = 0 // FinishedAt belongs to the previous run
	}
	if out.Name == "" {
		out.Name = id[:12]
	}
	return out, true
}

// Read lists the containers below root (DefaultRoot). nil = no <root>/containers folder: no docker section (not an
// error: the host has no Docker, or this user may not read it). A container whose file cannot be read or parsed is
// left out. Sorted by name, at most MaxContainers.
func Read(root string, now time.Time) *Inventory {
	ents, err := os.ReadDir(filepath.Join(root, "containers"))
	if err != nil {
		return nil
	}
	inv := &Inventory{At: now.Unix(), Containers: []Container{}}
	for _, e := range ents {
		if !e.IsDir() || !ValidID(e.Name()) {
			continue
		}
		f, err := os.Open(filepath.Join(root, "containers", e.Name(), "config.v2.json"))
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(f, maxConfigFile+1))
		f.Close()
		if err != nil || len(b) > maxConfigFile {
			continue
		}
		if c, ok := parse(b, e.Name()); ok {
			inv.Containers = append(inv.Containers, c)
		}
	}
	sort.Slice(inv.Containers, func(i, j int) bool {
		a, b := inv.Containers[i], inv.Containers[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
	if len(inv.Containers) > MaxContainers {
		inv.Containers = inv.Containers[:MaxContainers]
	}
	return inv
}
