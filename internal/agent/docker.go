package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/dockerinv"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

// Docker containers (v0.34.0), the agent's half. Names and states come from root's service scan (the `docker`
// section of inventory.json, see internal/dockerinv); the numbers come from here: every 60 s this reader (user
// monitoring-agent, no Docker socket, no group) reads the cgroup v2 files of each container
//
//	/sys/fs/cgroup/system.slice/docker-<id>.scope/{cpu.stat,memory.current,memory.max}
//
// (they are world-readable) and serves them as Prometheus text on 127.0.0.1:9479/metrics for the collector, which
// scrapes it only when host.env has DOCKER_MON=on. Only when answers.yaml agent.docker.allow. Without cgroup v2 it
// exports nothing and says so once.
const (
	// DockerPort is the loopback port of the metrics (the contract with the collector's base config).
	DockerPort      = 9479
	dockerEvery     = 60 * time.Second
	dockerCgroup    = "/sys/fs/cgroup"
	maxDockerSeries = 1000
)

// dockerNames reads the container names of the newest scan (<prefix>/inventory.json, docker section).
func dockerNames(prefix string) map[string]dockerinv.Container {
	b, err := os.ReadFile(filepath.Join(prefix, generate.InventoryFile))
	if err != nil {
		return nil
	}
	var doc struct {
		Docker *dockerinv.Inventory `json:"docker"`
	}
	if json.Unmarshal(b, &doc) != nil || doc.Docker == nil {
		return nil
	}
	m := make(map[string]dockerinv.Container, len(doc.Docker.Containers))
	for _, c := range doc.Docker.Containers {
		if dockerinv.ValidID(c.ID) {
			m[c.ID] = c
		}
	}
	return m
}

func readUint(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return n, err == nil
}

// cpuUsec reads usage_usec from a cgroup v2 cpu.stat.
func cpuUsec(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "usage_usec" {
			n, err := strconv.ParseUint(f[1], 10, 64)
			return n, err == nil
		}
	}
	return 0, false
}

func promLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// errNoCgroupV2: the host does not use the unified cgroup hierarchy.
var errNoCgroupV2 = errors.New("cgroup v2 not found")

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// collectDocker builds the Prometheus text: one series per container that has a cgroup scope now (the ones in the
// newest scan and any other docker-<id>.scope that is present). A container not in the scan yet is named by its
// 12-hex id with an empty project / service. n = containers exported.
func collectDocker(cgroupRoot, prefix string) ([]byte, int, error) {
	if _, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err != nil {
		return nil, 0, errNoCgroupV2
	}
	names := dockerNames(prefix)
	slice := filepath.Join(cgroupRoot, "system.slice")
	dirs := map[string]string{}
	if ents, err := os.ReadDir(slice); err == nil {
		for _, e := range ents {
			n := e.Name()
			if !strings.HasPrefix(n, "docker-") {
				continue
			}
			if id, ok := strings.CutSuffix(strings.TrimPrefix(n, "docker-"), ".scope"); ok && dockerinv.ValidID(id) {
				dirs[id] = filepath.Join(slice, n)
			}
		}
	}
	for id := range names { // the cgroupfs driver keeps them in docker/<id>
		if _, ok := dirs[id]; !ok {
			if p := filepath.Join(cgroupRoot, "docker", id); dirExists(p) {
				dirs[id] = p
			}
		}
	}
	ids := make([]string, 0, len(dirs))
	for id := range dirs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) > maxDockerSeries/3 {
		ids = ids[:maxDockerSeries/3]
	}
	var cpu, mem, lim bytes.Buffer
	n := 0
	for _, id := range ids {
		d := dirs[id]
		mcur, okMem := readUint(filepath.Join(d, "memory.current"))
		ucpu, okCPU := cpuUsec(filepath.Join(d, "cpu.stat"))
		if !okMem && !okCPU {
			continue // the container just went away
		}
		c := names[id]
		name := c.Name
		if name == "" {
			name = id[:12]
		}
		lbl := fmt.Sprintf(`{container_id="%s",container_name="%s",compose_project="%s",compose_service="%s"}`,
			id[:12], promLabel(name), promLabel(c.Project), promLabel(c.Service))
		if okCPU {
			fmt.Fprintf(&cpu, "docker_container_cpu_seconds_total%s %s\n", lbl, strconv.FormatFloat(float64(ucpu)/1e6, 'f', 6, 64))
		}
		if okMem {
			fmt.Fprintf(&mem, "docker_container_memory_bytes%s %d\n", lbl, mcur)
		}
		if m, ok := readUint(filepath.Join(d, "memory.max")); ok { // "max" = no limit: the series is left out
			fmt.Fprintf(&lim, "docker_container_memory_limit_bytes%s %d\n", lbl, m)
		}
		n++
	}
	var out bytes.Buffer
	if cpu.Len() > 0 {
		out.WriteString("# HELP docker_container_cpu_seconds_total CPU time used by the container (cgroup cpu.stat usage_usec).\n# TYPE docker_container_cpu_seconds_total counter\n")
		out.Write(cpu.Bytes())
	}
	if mem.Len() > 0 {
		out.WriteString("# HELP docker_container_memory_bytes Memory used by the container (cgroup memory.current).\n# TYPE docker_container_memory_bytes gauge\n")
		out.Write(mem.Bytes())
	}
	if lim.Len() > 0 {
		out.WriteString("# HELP docker_container_memory_limit_bytes Memory limit of the container (cgroup memory.max; no series without a limit).\n# TYPE docker_container_memory_limit_bytes gauge\n")
		out.Write(lim.Bytes())
	}
	return out.Bytes(), n, nil
}

// dockerExporter starts / stops the reader to follow answers.yaml agent.docker.allow (read again every poll).
type dockerExporter struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// set starts the reader when allow turned on and stops it when it turned off.
func (d *dockerExporter) set(ctx context.Context, cfg Config, allow bool) {
	switch {
	case allow && d.cancel == nil:
		c, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		d.cancel, d.done = cancel, done
		go func() {
			defer close(done)
			runDocker(c, cfg)
		}()
	case !allow && d.cancel != nil:
		d.stop()
	}
}

func (d *dockerExporter) stop() {
	if d.cancel != nil {
		d.cancel()
		<-d.done
		d.cancel, d.done = nil, nil
	}
}

// runDocker serves /metrics until ctx ends. The text is rebuilt every 60 s (the collector scrapes every 60 s).
func runDocker(ctx context.Context, cfg Config) {
	root, addr, every := cfg.DockerCgroup, cfg.DockerAddr, cfg.DockerEvery
	if root == "" {
		root = dockerCgroup
	}
	if addr == "" {
		addr = fmt.Sprintf("127.0.0.1:%d", DockerPort)
	}
	if every == 0 {
		every = dockerEvery
	}
	lg := cfg.Log
	if lg == nil {
		lg = log.New(os.Stderr, "", 0)
	}
	var mu sync.RWMutex
	body := []byte{}
	warned := false
	refresh := func() {
		b, n, err := collectDocker(root, cfg.Prefix)
		if err != nil {
			if !warned {
				lg.Printf("agent: docker metrics: %v under %s: nothing exported", err, root)
				warned = true
			}
			b = nil
		} else if warned {
			lg.Printf("agent: docker metrics: cgroup v2 found, %d containers", n)
			warned = false
		}
		mu.Lock()
		body = b
		mu.Unlock()
	}
	refresh()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		b := body
		mu.RUnlock()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Write(b)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	var ln net.Listener
	lastErr := ""
	for ln == nil {
		var err error
		if ln, err = net.Listen("tcp", addr); err != nil {
			ln = nil
			if err.Error() != lastErr {
				lg.Printf("agent: docker metrics: cannot listen on %s: %v (tried again every %s)", addr, err, every)
				lastErr = err.Error()
			}
			if !sleep(ctx, every) {
				return
			}
		}
	}
	lg.Printf("agent: docker metrics on http://%s/metrics", ln.Addr())
	go srv.Serve(ln)
	defer srv.Close()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			refresh()
		}
	}
}
