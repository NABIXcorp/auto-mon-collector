package agent_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/agent/agenttest"
)

func TestBootstrap(t *testing.T) {
	cp := agenttest.New()
	cp.Allow = "domains: [example.com]\nports: [443]\n"
	srv := httptest.NewServer(cp)
	defer srv.Close()
	base := srv.URL + "/agent/"

	b, err := agent.Bootstrap(context.Background(), base, "vm-web-01", agenttest.Token, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b.Project != "CI" || b.HostName != "vm-web-01" || b.Agent.URL != base || b.Agent.ControlPlaneKey != cp.PublicKey() ||
		!b.Agent.SiteAllow || b.Agent.UpdateAllow || !strings.Contains(b.Allow, "example.com") {
		t.Fatalf("bundle: %+v", b)
	}
	a := b.Answers()
	if err := a.Validate(); err != nil || a.HostName != "vm-web-01" || a.Agent == nil || !a.Agent.Site.Allow {
		t.Fatalf("answers: %+v %v", a, err)
	}
	if s := b.Secrets(); s["OO_AUTH"] != "Bearer smo_test" || s["OO_ENDPOINT"] == "" {
		t.Fatalf("secrets keys: %d", len(s))
	}
	if cp.Enrolled("vm-web-01") {
		t.Fatal("bootstrap used the token up")
	}
	// a wrong token: the console's reason, never the token
	_, err = agent.Bootstrap(context.Background(), base, "vm-web-01", "secret-wrong-token", nil)
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "secret-wrong-token") {
		t.Fatalf("wrong token: %v", err)
	}
}

func TestConsoleURLAndBundleCheck(t *testing.T) {
	for _, ok := range []string{"https://agent.example.com/agent/", "http://127.0.0.1:18091/agent/", "http://localhost:1/x/"} {
		if err := agent.ConsoleURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://agent.example.com/agent/", "https://agent.example.com/agent", "https://u:p@a.example/x/", "ftp://a/x/", ""} {
		if agent.ConsoleURL(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	var b agent.Bundle
	if b.Check() == nil {
		t.Error("empty bundle accepted")
	}
	b.Project, b.HostName = "P", "h"
	b.Agent.URL, b.Agent.ControlPlaneKey = "https://a.example/agent/", agenttest.New().PublicKey()
	b.OTLP.Endpoint, b.OTLP.Authorization = "https://a.example/agent/otlp", "Bearer smo_x"
	if err := b.Check(); err != nil {
		t.Fatal(err)
	}
	b.OTLP.Endpoint = "http://a.example/agent/otlp"
	if b.Check() == nil {
		t.Error("http OTLP endpoint accepted")
	}
	b.OTLP.Endpoint, b.OTLP.Authorization = "https://a.example/agent/otlp", "Bearer x'\nOO_ENDPOINT=evil"
	if b.Check() == nil {
		t.Error("an authorization that breaks the env file accepted")
	}
	b.OTLP.Authorization, b.ReleaseMirror = "Bearer smo_x", "http://mirror/"
	if b.Check() == nil {
		t.Error("http mirror accepted")
	}
}
