package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

// KeyFile (below the prefix): the host's Ed25519 private key (seed, base64), monitoring-agent 600.
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
	UnauthRetry     time.Duration // 12 s: one quick retry after the FIRST 401 (v0.14.0)
}

// Local is the host owner's side: answers (own probes + agent section) and the effective allowlist.
type Local struct {
	HostName string // answers host_name ("" = the OS hostname): the name the agent enrols and reports as
	Probes   generate.Probes
	Agent    generate.Agent
	Allow    generate.Allow
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
	return Local{HostName: a.HostName, Probes: a.Probes, Agent: *a.Agent, Allow: tmpl.Merge(a.Agent.Allow)}, nil
}

func (c *Config) defaults() {
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
	if c.UnauthRetry == 0 {
		c.UnauthRetry = 12 * time.Second
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
	unauth := 0      // 401s in a row
	sentInv := ""    // hash of the last inventory the control plane took (or refused): sent again only when it changes
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
			lg.Printf("agent: not enrolled (%v): run `sudo monitoring-agent agent enrol --token-stdin`", err)
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
		host := hostOf(cfg.Host, local)
		cl := &Client{Base: local.Agent.URL, Host: host, Key: key, HTTP: cfg.HTTP, Now: cfg.Now}
		if !reportUpdateResult(ctx, cfg, cl, &st) || !reportSiteResult(ctx, cfg, cl, &st) {
			return nil
		}
		if body, sum := inventoryBody(cfg.Prefix, cfg.Versions, st.Revision, local.Agent.Update.Allow, local.Agent.Site.Allow); sum != sentInv {
			var refused *RefusedError
			switch err := cl.SendInventory(ctx, body); {
			case err == nil:
				sentInv = sum
				lg.Printf("agent: inventory sent (revision %d)", st.Revision)
			case errors.As(err, &refused):
				sentInv = sum // the same body gets the same answer: wait for a change (or the next start)
				lg.Printf("agent: inventory: %v (not sent again until it changes)", err)
			case ctx.Err() != nil:
				return nil
			default:
				lg.Printf("agent: inventory: %v (retried with the next poll)", err)
			}
		}
		raw, err := cl.Desired(ctx, seen)
		switch {
		case ctx.Err() != nil:
			return nil
		case errors.Is(err, ErrUnauthorized):
			// One quick retry first (a new request = a fresh nonce): right after a control-plane restart a proxy can
			// re-send the open long poll with the SAME nonce -> 401 "nonce reused"; before v0.14.0 the agent then
			// waited its full backoff (up to 5 min). A real refusal (revoked, clock skew) gets 401 again -> backoff.
			if unauth++; unauth == 1 {
				lg.Printf("agent: %v: retrying once in %s", err, cfg.UnauthRetry)
				if !sleep(ctx, cfg.UnauthRetry) {
					return nil
				}
				continue
			}
			lg.Printf("agent: %v", err)
			wait(cfg.MaxBackoff)
			continue
		case err != nil:
			lg.Printf("agent: %v (retrying)", err)
			wait(0)
			continue
		case raw == nil:
			backoff, unauth = 0, 0
			continue
		}
		backoff, unauth = 0, 0
		doc, verr := Verify(raw, ed25519.PublicKey(cpKey), host, st.Revision, cfg.Now(), local.Allow)
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
				next := st
				next.Revision, next.Probes, next.At = doc.Revision, doc.Probes, cfg.Now().Unix()
				// v0.16.0: an update request is handled once per id (a later revision may repeat it until the
				// control plane has the result). The id is saved BEFORE the root unit starts.
				var upd *UpdateStatus
				var site *SiteStatus
				start := false
				if u := doc.Update; u != nil && u.ID != st.UpdateID {
					us, ok := prepareUpdate(cfg.Prefix, local.Agent.Update, cfg.Versions[VersionKey], u, raw)
					upd, start, next.UpdateID = &us, ok, u.ID
				} else if s := doc.Site; s != nil && s.Revision != st.SiteRevision {
					// v0.23.0: one root job per document: an overlay set waits while an update is handed over
					ss, ok := prepareSite(cfg.Prefix, local.Agent.Site, s, raw)
					site, start, next.SiteRevision = &ss, ok, s.Revision
				}
				if err := saveState(cfg.Prefix, next); err != nil {
					status.Result, status.Detail = "error", "applied, but "+StateFile+": "+err.Error()
					break
				}
				n := len(doc.Probes.TCP) + len(doc.Probes.HTTP) + len(doc.Probes.Ping)
				status.Result, status.Detail = "applied", fmt.Sprintf("%d probes", n)
				if restarted {
					status.Detail += ", Cloudprober restarted"
				}
				if start && upd != nil {
					us := startUpdate(cfg.Run, *upd)
					upd = &us
				}
				if start && site != nil {
					ss := startSite(cfg.Run, *site)
					site = &ss
				}
				if site != nil {
					status.Site = site
					lg.Printf("agent: overlays revision %d: %s: %s", site.Revision, site.Result, site.Detail)
				}
				if upd != nil {
					status.Update = upd
					lg.Printf("agent: update %s to %s: %s: %s", upd.ID, upd.To, upd.Result, upd.Detail)
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

// reportUpdateResult (v0.16.0) sends root's update result once (<prefix>/agent/update-result.json, id not reported
// yet). A refusal (4xx) also counts as reported; other errors are retried with the next poll. false = ctx ended.
func reportUpdateResult(ctx context.Context, cfg Config, cl *Client, st *State) bool {
	r, err := LoadUpdateResult(cfg.Prefix)
	if err != nil {
		cfg.Log.Printf("agent: %s: %v", UpdateResultFile, err)
		return true
	}
	if r.ID == "" || r.ID == st.UpdateReported {
		return true
	}
	s := Status{Revision: st.Revision, Result: "applied", Detail: "update " + r.ID + ": " + r.Result, Versions: cfg.Versions,
		Update: &UpdateStatus{ID: r.ID, Result: r.Result, Detail: r.Detail, From: r.From, To: r.To}}
	var refused *RefusedError
	switch err := cl.Report(ctx, s); {
	case ctx.Err() != nil:
		return false
	case err == nil, errors.As(err, &refused):
		if err != nil {
			cfg.Log.Printf("agent: update %s result: %v (not sent again)", r.ID, err)
		}
		next := *st
		next.UpdateReported = r.ID
		if err := saveState(cfg.Prefix, next); err != nil {
			cfg.Log.Printf("agent: %s: %v", StateFile, err)
			return true
		}
		*st = next
		cfg.Log.Printf("agent: update %s (%s -> %s): %s reported", r.ID, r.From, r.To, r.Result)
	default:
		cfg.Log.Printf("agent: update %s result: %v (retried with the next poll)", r.ID, err)
	}
	return true
}

// maxInventory: a larger inventory.json is not sent (the control plane caps request bodies).
const maxInventory = 48 << 10

// inventoryBody builds the inventory request and its hash.
func inventoryBody(prefix string, versions map[string]string, revision int64, updateAllowed, siteAllowed bool) ([]byte, string) {
	inv := Inventory{Versions: versions, Revision: revision, Services: json.RawMessage("null"), UpdateAllowed: updateAllowed, SiteAllowed: siteAllowed}
	b, err := os.ReadFile(filepath.Join(prefix, generate.InventoryFile))
	switch {
	case os.IsNotExist(err):
		inv.Error = generate.InventoryFile + " missing: run `monitoring-agent update` (v0.15.0+)"
	case err != nil:
		inv.Error = err.Error()
	case len(b) > maxInventory:
		inv.Error = fmt.Sprintf("%s too large (%d bytes)", generate.InventoryFile, len(b))
	case !json.Valid(b):
		inv.Error = generate.InventoryFile + " is not valid JSON"
	default:
		var c bytes.Buffer
		_ = json.Compact(&c, b)
		inv.Services = c.Bytes()
	}
	body, _ := json.Marshal(inv)
	sum := sha256.Sum256(body)
	return body, hex.EncodeToString(sum[:])
}

// Enrol creates the host key, registers it with a one-time token and writes it (owner uid:gid, mode 600) only after
// the control plane accepted it.
func Enrol(ctx context.Context, prefix, host, token string, uid, gid int, httpc *http.Client) error {
	local, err := LoadLocal(prefix)
	if err != nil {
		return err
	}
	host = hostOf(host, local)
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

// hostOf: the name this agent enrols and reports as: the explicit one (tests), else the answers' host_name (the
// collector's host.name, e.g. "vm-web-01" on a VM called "docker"), else the OS hostname. The same name as the data.
func hostOf(explicit string, l Local) string {
	if explicit != "" {
		return explicit
	}
	if l.HostName != "" {
		return l.HostName
	}
	h, _ := os.Hostname()
	return h
}

// HostName: the name `agent enrol` uses for this host (see hostOf); "" when the answers cannot be read.
func HostName(prefix string) string {
	l, err := LoadLocal(prefix)
	if err != nil {
		return ""
	}
	return hostOf("", l)
}
