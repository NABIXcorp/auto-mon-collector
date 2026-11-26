package generate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/assets"
	"github.com/NABIXcorp/auto-mon-collector/internal/dockerinv"
)

func dockerAnswers(allow bool) Answers {
	a := agentAnswers(false)
	a.Docker = AgentDocker{Allow: allow}
	return Answers{Agent: a}
}

// v0.34.0: agent.docker.allow switches DOCKER_MON=on in host.env and the docker section of inventory.json; off (the
// default) = neither, even when the scan found containers
func TestDockerSwitch(t *testing.T) {
	inv := &dockerinv.Inventory{At: 1, Containers: []dockerinv.Container{{ID: strings.Repeat("a", 64), Name: "shop-a-web-1", State: "running"}}}

	out, err := Generate(Host{Docker: inv}, dockerAnswers(false))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out.HostEnv), "DOCKER_MON") || strings.Contains(string(out.Inventory), `"docker"`) {
		t.Errorf("switch off:\n%s\n%s", out.HostEnv, out.Inventory)
	}
	if out, _ := Generate(Host{Docker: inv}, Answers{}); strings.Contains(string(out.HostEnv), "DOCKER_MON") || strings.Contains(string(out.Inventory), `"docker"`) {
		t.Errorf("no agent section:\n%s\n%s", out.HostEnv, out.Inventory)
	}

	out, err = Generate(Host{Docker: inv}, dockerAnswers(true))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out.HostEnv), "DOCKER_MON=on\n") {
		t.Errorf("host.env:\n%s", out.HostEnv)
	}
	var doc InventoryDoc
	if err := json.Unmarshal(out.Inventory, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Docker == nil || len(doc.Docker.Containers) != 1 || doc.Docker.Containers[0].Name != "shop-a-web-1" {
		t.Errorf("inventory docker section: %s", out.Inventory)
	}

	// switch on, but no Docker state folder on this host: DOCKER_MON is on, no section
	out, _ = Generate(Host{}, dockerAnswers(true))
	if !strings.Contains(string(out.HostEnv), "DOCKER_MON=on\n") || strings.Contains(string(out.Inventory), `"docker"`) {
		t.Errorf("no docker here:\n%s\n%s", out.HostEnv, out.Inventory)
	}
}

// the base config scrapes 127.0.0.1:9479 only with DOCKER_MON=on (the contract with the agent's reader)
func TestDockerReceiverGate(t *testing.T) {
	cfg := string(assets.BaseConfig())
	for _, want := range []string{"prometheus/docker:", `port == 9479`, `"${env:DOCKER_MON:-off}" == "on"`, `targets: ["127.0.0.1:9479"]`, "job_name: docker"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config.yaml lacks %q", want)
		}
	}
}

func TestDockerAnswers(t *testing.T) {
	key := "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	load := func(docker string) (Answers, error) {
		p := filepath.Join(t.TempDir(), "answers.yaml")
		y := "agent:\n  url: https://agent.example.com/agent/\n  control_plane_key: \"" + key + "\"\n" + docker
		if err := os.WriteFile(p, []byte(y), 0o644); err != nil {
			t.Fatal(err)
		}
		return LoadAnswers(p)
	}
	a, err := load("  docker:\n    allow: true\n")
	if err != nil || !a.Agent.Docker.Allow {
		t.Fatalf("docker allow: %v %+v", err, a.Agent)
	}
	a, err = load("")
	if err != nil || a.Agent.Docker.Allow {
		t.Fatalf("default must be off: %v %+v", err, a.Agent)
	}
	if _, err = load("  docker:\n    allow: true\n    socket: true\n"); err == nil {
		t.Error("an unknown key under agent.docker must be an error")
	}
	if _, err = load("  docker:\n    allow: maybe\n"); err == nil {
		t.Error("allow must be a bool")
	}
}
