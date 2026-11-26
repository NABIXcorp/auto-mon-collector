package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

const dockerTestID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func dockerState(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	d := filepath.Join(root, "containers", dockerTestID)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `{"ID":"` + dockerTestID + `","Name":"/shop-a-db-1","Config":{"Image":"db:16","Env":["PASSWORD=hunter2"],
"Labels":{"com.docker.compose.project":"shop-a","com.docker.compose.service":"db"}},
"State":{"Running":true,"StartedAt":"2026-11-20T10:00:00Z","FinishedAt":"0001-01-01T00:00:00Z","Health":{"Status":"healthy"}}}`
	if err := os.WriteFile(filepath.Join(d, "config.v2.json"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	old := dockerRoot
	dockerRoot = root
	t.Cleanup(func() { dockerRoot = old })
	return root
}

func readDoc(t *testing.T, pre string) generate.InventoryDoc {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pre, generate.InventoryFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "hunter2") {
		t.Fatalf("environment leaked into inventory.json:\n%s", b)
	}
	var doc generate.InventoryDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// v0.34.0: the 15-min scan reads the container state files into inventory.json, only with agent.docker.allow
func TestScanReadsDockerContainers(t *testing.T) {
	dockerState(t)

	pre := scanPrefix(t, "  rescan:\n    allow: true\n  docker:\n    allow: true\n", memHost(map[string]string{"20": "dockerd"}))
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--prefix", pre}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	doc := readDoc(t, pre)
	if doc.Docker == nil || doc.Docker.At == 0 || len(doc.Docker.Containers) != 1 {
		t.Fatalf("docker section: %+v", doc.Docker)
	}
	c := doc.Docker.Containers[0]
	if c.ID != dockerTestID || c.Name != "shop-a-db-1" || c.Image != "db:16" || c.Project != "shop-a" || c.Service != "db" || c.State != "running" || c.Health != "healthy" {
		t.Errorf("container: %+v", c)
	}

	// switch off (the default): no docker section, although the folder is there
	pre = scanPrefix(t, "  rescan:\n    allow: true\n", memHost(map[string]string{"20": "dockerd"}))
	out.Reset()
	if code := run([]string{"scan", "--prefix", pre}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	if doc := readDoc(t, pre); doc.Docker != nil {
		t.Errorf("docker section without the switch: %+v", doc.Docker)
	}

	// switch on, no Docker state folder: no section, no error
	dockerRoot = filepath.Join(t.TempDir(), "none")
	pre = scanPrefix(t, "  rescan:\n    allow: true\n  docker:\n    allow: true\n", memHost(nil))
	out.Reset()
	if code := run([]string{"scan", "--prefix", pre}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	if doc := readDoc(t, pre); doc.Docker != nil {
		t.Errorf("docker section without a docker folder: %+v", doc.Docker)
	}
}
