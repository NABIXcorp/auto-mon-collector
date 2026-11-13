package main

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent/agenttest"
)

// The refusals before anything is changed (the full install runs in the CI e2e job: root, systemd).
func TestInstallRefuses(t *testing.T) {
	old := installNeedRoot
	installNeedRoot = false
	defer func() { installNeedRoot = old }()
	srv := httptest.NewServer(agenttest.New())
	defer srv.Close()
	console := srv.URL + "/agent/"
	run1 := func(stdin string, args ...string) (int, string) {
		agentStdin = strings.NewReader(stdin)
		defer func() { agentStdin = os.Stdin }()
		var out, errb bytes.Buffer
		c := run(append([]string{"install"}, args...), &out, &errb)
		return c, out.String() + errb.String()
	}
	prefix := t.TempDir()
	if c, out := run1(agenttest.Token+"\n", "--console", console, "--prefix", prefix); c != exitUsage || !strings.Contains(out, "--token-stdin") {
		t.Errorf("no --token-stdin: %d %s", c, out)
	}
	if c, out := run1(agenttest.Token+"\n", "--console", "http://agent.example.com/agent/", "--token-stdin", "--prefix", prefix); c != exitUsage || !strings.Contains(out, "https only") {
		t.Errorf("http console: %d %s", c, out)
	}
	if c, out := run1("\n", "--console", console, "--token-stdin", "--prefix", prefix); c != exitUsage || !strings.Contains(out, "no token") {
		t.Errorf("empty token: %d %s", c, out)
	}
	if c, out := run1("wrong-token\n", "--console", console, "--token-stdin", "--prefix", prefix, "--host", "h1"); c != exitUsage ||
		!strings.Contains(out, "HTTP 401") || strings.Contains(out, "wrong-token") {
		t.Errorf("wrong token: %d %s", c, out)
	}
	os.WriteFile(filepath.Join(prefix, "answers.yaml"), []byte("project: x\n"), 0o644)
	if c, out := run1(agenttest.Token+"\n", "--console", console, "--token-stdin", "--prefix", prefix); c != exitUsage || !strings.Contains(out, "installed already") {
		t.Errorf("installed host: %d %s", c, out)
	}
}
