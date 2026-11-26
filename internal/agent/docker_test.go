package agent

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func cid(n int) string { return fmt.Sprintf("%064x", n) }

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func scope(t *testing.T, root string, id string, cpuUsec int, mem int, max string) {
	t.Helper()
	d := filepath.Join(root, "system.slice", "docker-"+id+".scope")
	writeFile(t, filepath.Join(d, "cpu.stat"), fmt.Sprintf("usage_usec %d\nuser_usec 1\nsystem_usec 2\nnr_periods 0\n", cpuUsec))
	writeFile(t, filepath.Join(d, "memory.current"), fmt.Sprintf("%d\n", mem))
	writeFile(t, filepath.Join(d, "memory.max"), max+"\n")
}

func TestCollectDocker(t *testing.T) {
	cg, prefix := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(cg, "cgroup.controllers"), "cpu memory io\n")
	scope(t, cg, cid(1), 2_500_000, 1048576, "2097152")
	scope(t, cg, cid(2), 10_000_000, 512, "max") // no limit: no limit series
	scope(t, cg, cid(3), 1, 2, "max")            // not in the scan: named by its 12-hex id
	writeFile(t, filepath.Join(cg, "system.slice", "docker-notanid.scope", "cpu.stat"), "usage_usec 5\n")
	writeFile(t, filepath.Join(cg, "system.slice", "sshd.service", "cpu.stat"), "usage_usec 5\n")
	writeFile(t, filepath.Join(prefix, "inventory.json"), fmt.Sprintf(`{"schema":1,"docker":{"at":1,"containers":[
{"id":"%s","name":"shop-a-web-1","project":"shop-a","service":"web","state":"running"},
{"id":"%s","name":"lonely \"one\"","project":"","service":""}]}}`, cid(1), cid(2)))

	b, n, err := collectDocker(cg, prefix)
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	out := string(b)
	for _, want := range []string{
		"# TYPE docker_container_cpu_seconds_total counter\n",
		"# TYPE docker_container_memory_bytes gauge\n",
		"# TYPE docker_container_memory_limit_bytes gauge\n",
		`docker_container_cpu_seconds_total{container_id="000000000000",container_name="shop-a-web-1",compose_project="shop-a",compose_service="web"} 2.500000` + "\n",
		`docker_container_memory_bytes{container_id="000000000000",container_name="shop-a-web-1",compose_project="shop-a",compose_service="web"} 1048576` + "\n",
		`docker_container_memory_limit_bytes{container_id="000000000000",container_name="shop-a-web-1",compose_project="shop-a",compose_service="web"} 2097152` + "\n",
		`container_name="lonely \"one\"",compose_project="",compose_service=""} 10.000000` + "\n",
		`docker_container_memory_bytes{container_id="000000000000",container_name="000000000000",compose_project="",compose_service=""} 2` + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if c := strings.Count(out, "docker_container_memory_limit_bytes{"); c != 1 {
		t.Errorf("the limit series of a container without a limit must be left out: %d in\n%s", c, out)
	}
	if strings.Contains(out, "sshd") || strings.Contains(out, "notanid") {
		t.Errorf("non-container scopes exported:\n%s", out)
	}
}

func TestCollectDockerNoCgroupV2(t *testing.T) {
	cg := t.TempDir() // no cgroup.controllers = cgroup v1 / another layout
	scope(t, cg, cid(1), 1, 1, "max")
	if b, _, err := collectDocker(cg, t.TempDir()); err != errNoCgroupV2 || len(b) != 0 {
		t.Errorf("v1 layout: %q %v", b, err)
	}
}

func TestCollectDockerCgroupfsDriver(t *testing.T) {
	cg, prefix := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(cg, "cgroup.controllers"), "cpu memory\n")
	d := filepath.Join(cg, "docker", cid(7))
	writeFile(t, filepath.Join(d, "cpu.stat"), "usage_usec 3000000\n")
	writeFile(t, filepath.Join(d, "memory.current"), "4096\n")
	writeFile(t, filepath.Join(prefix, "inventory.json"), fmt.Sprintf(`{"docker":{"at":1,"containers":[{"id":"%s","name":"app","project":"","service":""}]}}`, cid(7)))
	b, n, err := collectDocker(cg, prefix)
	if err != nil || n != 1 || !strings.Contains(string(b), `container_name="app"`) {
		t.Errorf("n=%d err=%v\n%s", n, err, b)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	var last error
	for range 50 {
		resp, err := http.Get(url)
		if err == nil {
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(b)
		}
		last = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal(last)
	return 0, ""
}

// the switch: on = the reader serves /metrics (refreshed every tick), off = it stops
func TestDockerExporterFollowsTheSwitch(t *testing.T) {
	cg, prefix := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(cg, "cgroup.controllers"), "cpu memory\n")
	scope(t, cg, cid(1), 1_000_000, 100, "max")
	addr := freeAddr(t)
	var lb syncBuf
	cfg := Config{Prefix: prefix, Log: log.New(&lb, "", 0), DockerCgroup: cg, DockerAddr: addr, DockerEvery: 100 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var dk dockerExporter
	dk.set(ctx, cfg, false)
	if dk.cancel != nil {
		t.Fatal("started while off")
	}
	dk.set(ctx, cfg, true)
	code, body := get(t, "http://"+addr+"/metrics")
	if code != 200 || !strings.Contains(body, "docker_container_memory_bytes{") || !strings.Contains(body, " 100\n") {
		t.Fatalf("%d\n%s", code, body)
	}
	if code, _ := get(t, "http://"+addr+"/other"); code != 404 {
		t.Errorf("/other: %d", code)
	}
	// a new container shows up with the next refresh
	scope(t, cg, cid(2), 1, 200, "max")
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, body = get(t, "http://"+addr+"/metrics")
		if strings.Contains(body, " 200\n") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no refresh:\n%s", body)
		}
		time.Sleep(50 * time.Millisecond)
	}
	dk.set(ctx, cfg, false)
	if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		c.Close()
		t.Error("still listening after the switch went off")
	}
	dk.stop() // a second stop is harmless
}

// no cgroup v2: an empty /metrics, one log line (not one per refresh)
func TestDockerExporterWithoutCgroupV2(t *testing.T) {
	addr := freeAddr(t)
	var lb syncBuf
	cfg := Config{Prefix: t.TempDir(), Log: log.New(&lb, "", 0), DockerCgroup: t.TempDir(), DockerAddr: addr, DockerEvery: 30 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var dk dockerExporter
	dk.set(ctx, cfg, true)
	code, body := get(t, "http://"+addr+"/metrics")
	if code != 200 || body != "" {
		t.Errorf("%d %q", code, body)
	}
	time.Sleep(150 * time.Millisecond)
	dk.stop()
	if c := strings.Count(lb.String(), "cgroup v2 not found"); c != 1 {
		t.Errorf("logged %d times:\n%s", c, lb.String())
	}
}
