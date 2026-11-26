package dockerinv

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func hexID(n int) string { return fmt.Sprintf("%064x", n) }

// put writes <root>/containers/<id>/config.v2.json.
func put(t *testing.T, root, id, body string) {
	t.Helper()
	d := filepath.Join(root, "containers", id)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "config.v2.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// a compose container: with an environment, a command and a mount, which must never reach the inventory
const composeRunning = `{"ID":"%s","Name":"/shop-a-web-1","Path":"/srv/secret-command","Args":["--token=hunter2"],
"Config":{"Image":"shop/web:1.4","Env":["DB_PASSWORD=hunter2"],"Cmd":["run","--key=abc"],
"Labels":{"com.docker.compose.project":"shop-a","com.docker.compose.service":"web",
"com.docker.compose.project.working_dir":"/srv/shop-a","com.example.owner":"private-label"}},
"State":{"Running":true,"Paused":false,"Restarting":false,"Dead":false,"ExitCode":0,
"StartedAt":"2026-11-20T10:00:00.5Z","FinishedAt":"0001-01-01T00:00:00Z","Health":{"Status":"healthy","Log":[{"Output":"secret"}]}},
"RestartCount":2,"MountPoints":{"/data":{"Source":"/srv/private"}}}`

const manual = `{"ID":"%s","Name":"/tool","Config":{"Image":"tool:latest","Labels":null},
"State":{"Running":true,"StartedAt":"2026-11-21T00:00:00Z","FinishedAt":"0001-01-01T00:00:00Z"},"RestartCount":0}`

func exited(code int) string {
	return fmt.Sprintf(`{"ID":"%%s","Name":"/job-%d","Config":{"Image":"job:1","Labels":{"com.docker.compose.project":"shop-a","com.docker.compose.service":"job"}},
"State":{"Running":false,"ExitCode":%d,"StartedAt":"2026-11-20T10:00:00Z","FinishedAt":"2026-11-20T11:00:00Z"}}`, code, code)
}

func TestReadContainers(t *testing.T) {
	root := t.TempDir()
	put(t, root, hexID(1), fmt.Sprintf(composeRunning, hexID(1)))
	put(t, root, hexID(2), fmt.Sprintf(manual, hexID(2)))
	put(t, root, hexID(3), fmt.Sprintf(exited(0), hexID(3)))
	put(t, root, hexID(4), fmt.Sprintf(exited(1), hexID(4)))
	put(t, root, hexID(5), `{"ID":"`+hexID(5)+`","Name":"/loop","Config":{"Image":"x"},"State":{"Running":true,"Restarting":true,"ExitCode":137,"StartedAt":"2026-11-21T00:00:00Z","FinishedAt":"2026-11-21T00:00:05Z","Health":{"Status":"unhealthy"}},"RestartCount":9}`)
	put(t, root, hexID(6), `{"ID":"`+hexID(6)+`","Name":"/new","Config":{"Image":"x"},"State":{"StartedAt":"0001-01-01T00:00:00Z","FinishedAt":"0001-01-01T00:00:00Z"}}`)
	put(t, root, hexID(7), `{"ID":"`+hexID(7)+`","Name":"/gone","Config":{"Image":"x"},"State":{"Dead":true,"StartedAt":"2026-11-21T00:00:00Z"}}`)
	put(t, root, hexID(8), `{"ID":"`+hexID(8)+`","Name":"/waiting","Config":{"Image":"x"},"State":{"Running":true,"Paused":true,"StartedAt":"2026-11-21T00:00:00Z","Health":{"Status":"starting"}}}`)
	put(t, root, hexID(9), `not json`)
	put(t, root, "not-an-id", `{}`)

	now := time.Unix(1_800_000_000, 0)
	inv := Read(root, now)
	if inv == nil || inv.At != 1_800_000_000 {
		t.Fatalf("inventory: %+v", inv)
	}
	got := map[string]Container{}
	var names []string
	for _, c := range inv.Containers {
		got[c.Name] = c
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "gone,job-0,job-1,loop,new,shop-a-web-1,tool,waiting" {
		t.Fatalf("names (sorted, the broken ones left out): %v", names)
	}

	started, _ := time.Parse(time.RFC3339, "2026-11-20T10:00:00Z")
	web := got["shop-a-web-1"]
	want := Container{ID: hexID(1), Name: "shop-a-web-1", Image: "shop/web:1.4", Project: "shop-a", Service: "web", WorkingDir: "/srv/shop-a",
		State: "running", Health: "", Restarts: 2, StartedAt: started.Unix(), Ports: []Port{}}
	if !reflect.DeepEqual(web, want) {
		t.Errorf("compose container:\n got %+v\nwant %+v", web, want)
	}
	if c := got["tool"]; c.Project != "" || c.Service != "" || c.WorkingDir != "" || c.State != "running" || c.Health != "" {
		t.Errorf("non-compose container: %+v", c)
	}
	if c := got["job-0"]; c.State != "exited" || c.ExitCode != 0 || c.FinishedAt == 0 || c.StartedAt == 0 {
		t.Errorf("exited 0: %+v", c)
	}
	if c := got["job-1"]; c.State != "exited" || c.ExitCode != 1 {
		t.Errorf("exited 1: %+v", c)
	}
	if c := got["loop"]; c.State != "restarting" || c.Health != "" || c.Restarts != 9 || c.FinishedAt != 0 {
		t.Errorf("restarting: %+v", c)
	}
	if c := got["new"]; c.State != "created" || c.StartedAt != 0 || c.FinishedAt != 0 {
		t.Errorf("created: %+v", c)
	}
	if c := got["gone"]; c.State != "dead" {
		t.Errorf("dead: %+v", c)
	}
	if c := got["waiting"]; c.State != "paused" || c.Health != "" {
		t.Errorf("paused: %+v", c)
	}
}

// nothing but the allowlisted fields can reach the JSON
func TestNoSecretsCopied(t *testing.T) {
	root := t.TempDir()
	put(t, root, hexID(1), fmt.Sprintf(composeRunning, hexID(1)))
	inv := Read(root, time.Now())
	b := fmt.Sprintf("%+v", inv)
	for _, bad := range []string{"hunter2", "secret", "private", "--key"} {
		if strings.Contains(b, bad) {
			t.Errorf("%q copied into %s", bad, b)
		}
	}
}

func TestNoDockerFolder(t *testing.T) {
	if inv := Read(t.TempDir(), time.Now()); inv != nil {
		t.Errorf("no /containers folder: %+v", inv)
	}
	if inv := Read(filepath.Join(t.TempDir(), "missing"), time.Now()); inv != nil {
		t.Errorf("missing root: %+v", inv)
	}
	// an empty folder is an empty list, not nil
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "containers"), 0o755)
	if inv := Read(root, time.Now()); inv == nil || inv.Containers == nil || len(inv.Containers) != 0 {
		t.Errorf("empty: %+v", inv)
	}
}

func TestCapAndClip(t *testing.T) {
	root := t.TempDir()
	long := strings.Repeat("é", 150) // 300 bytes
	for i := 1; i <= MaxContainers+5; i++ {
		put(t, root, hexID(i), fmt.Sprintf(`{"ID":"%s","Name":"/c%04d","Config":{"Image":" %s ","Labels":{"com.docker.compose.project":"  p  "}},"State":{"Running":true,"StartedAt":"2026-11-21T00:00:00Z"}}`,
			hexID(i), i, long))
	}
	inv := Read(root, time.Now())
	if len(inv.Containers) != MaxContainers {
		t.Fatalf("%d containers, want %d", len(inv.Containers), MaxContainers)
	}
	if inv.Containers[0].Name != "c0001" || inv.Containers[MaxContainers-1].Name != fmt.Sprintf("c%04d", MaxContainers) {
		t.Errorf("the first 300 by name are kept: %s .. %s", inv.Containers[0].Name, inv.Containers[MaxContainers-1].Name)
	}
	img := inv.Containers[0].Image
	if len(img) > 200 || !strings.HasPrefix(img, "é") || strings.ContainsRune(img, '�') {
		t.Errorf("image not clipped to 200 bytes on a character border: %d bytes", len(img))
	}
	if inv.Containers[0].Project != "p" {
		t.Errorf("project not trimmed: %q", inv.Containers[0].Project)
	}
}

// the ID in the file is missing: the folder name is the id
func TestIDFromFolder(t *testing.T) {
	root := t.TempDir()
	put(t, root, hexID(1), `{"Name":"/a","Config":{"Image":"x"},"State":{"Running":true,"StartedAt":"2026-11-21T00:00:00Z"}}`)
	inv := Read(root, time.Now())
	if len(inv.Containers) != 1 || inv.Containers[0].ID != hexID(1) {
		t.Errorf("%+v", inv.Containers)
	}
}

// v0.34.1: published ports from NetworkSettings.Ports; exposed-only and bad entries are left out, sorted.
func TestPortsOf(t *testing.T) {
	b := []byte(`{"ID":"` + hexID(1) + `","Name":"/web","Config":{"Image":"x"},"State":{"Running":true},
"NetworkSettings":{"Ports":{"8085/tcp":[{"HostIp":"::","HostPort":"8085"},{"HostIp":"0.0.0.0","HostPort":"8085"}],
"9000/tcp":null,"53/udp":[{"HostIp":"127.0.0.1","HostPort":"5353"}],"x/tcp":[{"HostIp":"0.0.0.0","HostPort":"1"}],
"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"nope"}]}}}`)
	c, ok := parse(b, hexID(1))
	if !ok {
		t.Fatal("parse")
	}
	want := []Port{{IP: "127.0.0.1", Port: 5353, Target: 53, Proto: "udp"}, {IP: "0.0.0.0", Port: 8085, Target: 8085, Proto: "tcp"},
		{IP: "::", Port: 8085, Target: 8085, Proto: "tcp"}}
	if len(c.Ports) != len(want) {
		t.Fatalf("ports %+v", c.Ports)
	}
	for i := range want {
		if c.Ports[i] != want[i] {
			t.Fatalf("port %d: %+v, want %+v", i, c.Ports[i], want[i])
		}
	}
	if c2, _ := parse([]byte(`{"ID":"`+hexID(2)+`","Name":"/x","Config":{"Image":"x"},"State":{}}`), hexID(2)); c2.Ports == nil || len(c2.Ports) != 0 {
		t.Fatalf("no ports = empty list: %+v", c2.Ports)
	}
}
