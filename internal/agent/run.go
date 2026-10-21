package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

// KeyFile (below the prefix): the host's Ed25519 private key (seed, base64), amc-agent 600.
const KeyFile = "agent/key"

// Config of one agent process.
type Config struct {
	Prefix   string
	Host     string            // "" = os.Hostname() (the collector's host.name source)
	Versions map[string]string // reported with every status
	Run      Runner
	HTTP     *http.Client
	Log      *log.Logger
	Now      func() time.Time
	// test knobs (0 = defaults)
	NotEnrolledWait time.Duration // 15 s
	MaxBackoff      time.Duration // 5 min
}

// Local is the host owner's side: answers (own probes + agent section) and the effective allowlist.
type Local struct {
	Probes generate.Probes
	Agent  generate.Agent
	Allow  generate.Allow
}

// LoadLocal reads <prefix>/answers.yaml and the project template <prefix>/config/agent-allow.yaml (if any).
func LoadLocal(prefix string) (Local, error) {
	var l Local
	a, err := generate.LoadAnswers(filepath.Join(prefix, "answers.yaml"))
	if err != nil {
		return l, err
	}
	if a.Agent == nil {
		return l, errors.New("answers.yaml has no agent section: the agent is not configured on this host")
	}
	var tmpl generate.Allow
	p := filepath.Join(prefix, filepath.FromSlash(generate.AllowFile))
	if _, err := os.Stat(p); err == nil {
		if tmpl, err = generate.LoadAllow(p); err != nil {
			return l, err
		}
	}
	return Local{Probes: a.Probes, Agent: *a.Agent, Allow: tmpl.Merge(a.Agent.Allow)}, nil
}

func (c *Config) defaults() {
	if c.Host == "" {
		c.Host, _ = os.Hostname()
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 90 * time.Second} // > the 60 s long poll
	}
	if c.Log == nil {
		c.Log = log.New(os.Stderr, "", 0) // journald adds the time
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.NotEnrolledWait == 0 {
		c.NotEnrolledWait = 15 * time.Second
	}
	if c.MaxBackoff == 0 {
		c.MaxBackoff = 5 * time.Minute
	}
}

func loadKey(prefix string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(filepath.Join(prefix, filepath.FromSlash(KeyFile)))
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("key file is damaged: enrol again")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Run is the daemon loop. It never exits on errors (backoff instead), only when ctx ends.
func Run(ctx context.Context, cfg Config) error {
	cfg.defaults()
	lg := cfg.Log
	backoff := time.Duration(0)
	wait := func(base time.Duration) bool {
		if backoff == 0 {
			backoff = 5 * time.Second
		} else if backoff *= 2; backoff > cfg.MaxBackoff {
			backoff = cfg.MaxBackoff
		}
		if base > backoff {
			backoff = base
		}
		return sleep(ctx, backoff/2+time.Duration(mrand.Int64N(int64(backoff/2)+1))) // jitter
	}
	seen := int64(0) // highest revision handled (applied or rejected): never fetch the same one again
	for ctx.Err() == nil {
		local, err := LoadLocal(cfg.Prefix)
		if err != nil {
			lg.Printf("agent: %v", err)
			if !sleep(ctx, cfg.NotEnrolledWait) {
				break
			}
			continue
		}
		key, err := loadKey(cfg.Prefix)
		if err != nil {
			lg.Printf("agent: not enrolled (%v): run `sudo amc agent enrol --token-stdin`", err)
			if !sleep(ctx, cfg.NotEnrolledWait) {
				break
			}
			continue
		}
		cpKey, _ := generate.ParseKey(local.Agent.ControlPlaneKey) // validated with the answers
		st, err := LoadState(cfg.Prefix)
		if err != nil {
			lg.Printf("agent: %s: %v", StateFile, err)
		}
		seen = max(seen, st.Revision)
		cl := &Client{Base: local.Agent.URL, Host: cfg.Host, Key: key, HTTP: cfg.HTTP, Now: cfg.Now}
		raw, err := cl.Desired(ctx, seen)
		switch {
		case ctx.Err() != nil:
			return nil
		case errors.Is(err, ErrUnauthorized):
			lg.Printf("agent: %v", err)
			wait(cfg.MaxBackoff)
			continue
		case err != nil:
			lg.Printf("agent: %v (retrying)", err)
			wait(0)
			continue
		case raw == nil:
			backoff = 0
			continue
		}
		backoff = 0
		doc, verr := Verify(raw, ed25519.PublicKey(cpKey), cfg.Host, st.Revision, cfg.Now(), local.Allow)
		status := Status{Revision: doc.Revision, Versions: cfg.Versions}
		var rej *Reject
		switch {
		case errors.As(verr, &rej):
			status.Result, status.Detail = "rejected", rej.Reason
		case verr != nil:
			status.Result, status.Detail = "error", verr.Error()
		default:
			restarted, aerr := (&Applier{Prefix: cfg.Prefix, Run: cfg.Run}).Apply(local.Probes, doc.Probes)
			switch {
			case errors.As(aerr, &rej):
				status.Result, status.Detail = "rejected", rej.Reason
			case aerr != nil:
				status.Result, status.Detail = "error", aerr.Error()
			default:
				if err := saveState(cfg.Prefix, State{Revision: doc.Revision, Probes: doc.Probes}); err != nil {
					status.Result, status.Detail = "error", "applied, but "+StateFile+": "+err.Error()
					break
				}
				n := len(doc.Probes.TCP) + len(doc.Probes.HTTP) + len(doc.Probes.Ping)
				status.Result, status.Detail = "applied", fmt.Sprintf("%d probes", n)
				if restarted {
					status.Detail += ", Cloudprober restarted"
				}
			}
		}
		replay := doc.Revision <= seen // a control plane that sends an old revision again: do not spin on it
		if doc.Revision > seen && status.Result != "error" {
			seen = doc.Revision // a rejected revision is not fetched again; an error is retried
		}
		lg.Printf("agent: revision %d %s: %s", doc.Revision, status.Result, status.Detail)
		if err := cl.Report(ctx, status); err != nil && ctx.Err() == nil {
			lg.Printf("agent: report: %v", err)
		}
		if status.Result == "error" || replay {
			wait(0)
		}
	}
	return nil
}

// Enrol creates the host key, registers it with a one-time token and writes it (owner uid:gid, mode 600) only after
// the control plane accepted it.
func Enrol(ctx context.Context, prefix, host, token string, uid, gid int, httpc *http.Client) error {
	local, err := LoadLocal(prefix)
	if err != nil {
		return err
	}
	if host == "" {
		host, _ = os.Hostname()
	}
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	cl := &Client{Base: local.Agent.URL, Host: host, Key: priv, HTTP: httpc}
	if err := cl.Enrol(ctx, strings.TrimSpace(token)); err != nil {
		return err
	}
	p := filepath.Join(prefix, filepath.FromSlash(KeyFile))
	if err := writeAtomic(p, []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		return err
	}
	if uid < 0 {
		return nil // tests on a system without owners
	}
	return os.Lchown(p, uid, gid)
}
