package agent

// bootstrap.go (v0.24.0): `monitoring-agent install --console URL --token-stdin` asks the control plane for
// everything a new host needs: POST <console>v1/bootstrap {"host","token"} -> Bundle. The token is the host's
// one-time enrolment token; bootstrap only checks it (the enrolment at the end of install uses it up). The bundle
// holds no OpenObserve secret: the host sends to the control plane's OTLP gateway with its own revocable token.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

// Bundle is the control plane's answer to a bootstrap request.
type Bundle struct {
	Project  string `json:"project"`
	HostName string `json:"host_name"`
	Agent    struct {
		URL             string `json:"url"`
		ControlPlaneKey string `json:"control_plane_key"`
		UpdateAllow     bool   `json:"update_allow"`
		SiteAllow       bool   `json:"site_allow"`
	} `json:"agent"`
	Allow string `json:"allow"` // the project's agent allowlist template (YAML), "" = none
	OTLP  struct {
		Endpoint      string `json:"endpoint"`      // -> OO_ENDPOINT
		Authorization string `json:"authorization"` // -> OO_AUTH ("Bearer smo_..."), never printed
	} `json:"otlp"`
	ReleaseMirror string `json:"release_mirror"` // -> answers release_mirror ("" = GitHub only)
	// UseMirror: the console mirrors the release files at <console>dl/ (when ReleaseMirror is empty)
	UseMirror bool `json:"use_mirror"`
}

// defaults: what the console leaves out is relative to the URL install was given (a console behind a proxy
// does not know its public address): agent url = console, OTLP endpoint = <console>otlp, mirror = <console>dl/.
func (b *Bundle) defaults(console string) {
	if b.Agent.URL == "" {
		b.Agent.URL = console
	}
	if b.OTLP.Endpoint == "" {
		b.OTLP.Endpoint = console + "otlp"
	}
	if b.ReleaseMirror == "" && b.UseMirror && strings.HasPrefix(console, "https://") {
		b.ReleaseMirror = console + "dl/"
	}
}

// ConsoleURL: https, or http to a loopback address (tests); ends in "/".
func ConsoleURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || !strings.HasSuffix(u.Path, "/") {
		return fmt.Errorf("--console %q: a URL like https://agent.example.com/agent/", s)
	}
	if u.Scheme == "https" || (u.Scheme == "http" && loopback(u.Hostname())) {
		return nil
	}
	return fmt.Errorf("--console %q: https only (http only to 127.0.0.1)", s)
}

func loopback(h string) bool {
	ip := net.ParseIP(h)
	return h == "localhost" || (ip != nil && ip.IsLoopback())
}

// Check: the bundle is complete and its addresses are what install may write.
func (b *Bundle) Check() error {
	switch {
	case b.Project == "":
		return errors.New("bootstrap: no project")
	case b.HostName == "":
		return errors.New("bootstrap: no host name")
	case b.OTLP.Endpoint == "" || b.OTLP.Authorization == "":
		return errors.New("bootstrap: no OTLP endpoint / authorization")
	case strings.ContainsAny(b.OTLP.Authorization, "'\n\r"):
		return errors.New("bootstrap: OTLP authorization has characters an env file cannot hold")
	}
	if err := ConsoleURL(b.Agent.URL); err != nil {
		return fmt.Errorf("bootstrap: agent url: %w", err)
	}
	if err := ConsoleURL(strings.TrimSuffix(b.OTLP.Endpoint, "/") + "/"); err != nil {
		return fmt.Errorf("bootstrap: otlp endpoint: %w", err)
	}
	if _, err := generate.ParseKey(b.Agent.ControlPlaneKey); err != nil {
		return fmt.Errorf("bootstrap: control plane key: %w", err)
	}
	return generate.ValidMirror(b.ReleaseMirror)
}

// Answers: what install writes as <prefix>/answers.yaml (no secrets).
func (b *Bundle) Answers() generate.Answers {
	a := generate.Answers{Project: b.Project, HostName: b.HostName, ReleaseMirror: b.ReleaseMirror,
		Agent: &generate.Agent{URL: b.Agent.URL, ControlPlaneKey: b.Agent.ControlPlaneKey}}
	a.Agent.Update.Allow = b.Agent.UpdateAllow
	a.Agent.Site.Allow = b.Agent.SiteAllow
	return a
}

// Secrets: secrets/collector.env of the new host (OO_* = the gateway, not OpenObserve itself).
func (b *Bundle) Secrets() map[string]string {
	return map[string]string{"OO_ENDPOINT": b.OTLP.Endpoint, "OO_AUTH": b.OTLP.Authorization}
}

// Bootstrap asks the control plane at base for host's bundle. Errors never contain the token.
func Bootstrap(ctx context.Context, base, host, token string, httpc *http.Client) (Bundle, error) {
	var b Bundle
	if err := ConsoleURL(base); err != nil {
		return b, err
	}
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}
	body, _ := json.Marshal(map[string]string{"host": host, "token": strings.TrimSpace(token)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"v1/bootstrap", bytes.NewReader(body))
	if err != nil {
		return b, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "monitoring-agent")
	resp, err := httpc.Do(req)
	if err != nil {
		return b, fmt.Errorf("bootstrap: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = http.StatusText(resp.StatusCode)
		}
		return b, fmt.Errorf("bootstrap: HTTP %d: %s", resp.StatusCode, e.Error)
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return b, fmt.Errorf("bootstrap: answer not readable: %w", err)
	}
	b.defaults(base)
	return b, b.Check()
}
