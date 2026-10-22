// Package agenttest is a fake control plane for tests and the CI end-to-end run: it enrols hosts with a fixed
// token, checks the request signatures like a real control plane and serves signed probe documents that a test
// publishes through /_test/*. Never part of a release binary.
package agenttest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

// Token is the one enrolment token the fake accepts.
const Token = "test-enrol-token-0123456789"

// Server is the fake control plane.
type Server struct {
	Priv ed25519.PrivateKey
	Poll time.Duration // long poll (default 2 s)

	mu       sync.Mutex
	hosts    map[string]ed25519.PublicKey
	docs     map[string][]byte // host -> raw signed document (the newest)
	revs     map[string]int64
	maxRev   map[string]int64
	force    map[string]bool // serve the stored document even when it is not newer than ?have= (replay test)
	statuses []agent.Status
	wake     chan struct{}
	refuse   int // answer the next N signed requests with 401 (a proxy re-sending an old request after a restart)
}

// Refuse401 makes the next n signed requests fail with 401 ("nonce reused" after a control-plane restart).
func (s *Server) Refuse401(n int) {
	s.mu.Lock()
	s.refuse = n
	s.mu.Unlock()
}

// New makes a fake with a fresh control-plane key.
func New() *Server {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &Server{Priv: priv, Poll: 2 * time.Second, hosts: map[string]ed25519.PublicKey{}, docs: map[string][]byte{},
		revs: map[string]int64{}, force: map[string]bool{}, maxRev: map[string]int64{}, wake: make(chan struct{})}
}

// PublicKey as written in the answers.
func (s *Server) PublicKey() string { return agent.EncodeKey(s.Priv.Public().(ed25519.PublicKey)) }

// Publish signs a document for host. tamper = change it after signing; key = sign with another key; expires = 0
// means +1 h. Returns the revision.
func (s *Server) Publish(host string, rev int64, p generate.Probes, expires int64, tamper, otherKey bool) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.force[host] = rev != 0 && rev <= s.revs[host] // an explicit old revision = a replay: served anyway
	if rev == 0 {
		rev = max(s.revs[host], s.maxRev[host]) + 1
	}
	s.maxRev[host] = max(s.maxRev[host], rev)
	now := time.Now().Unix()
	if expires == 0 {
		expires = now + 3600
	}
	doc := map[string]any{"host": host, "revision": rev, "issued_at": now, "expires_at": expires, "probes": p}
	b, _ := json.Marshal(doc)
	c, _ := agent.CanonicalJSON(b)
	key := s.Priv
	if otherKey {
		_, key, _ = ed25519.GenerateKey(rand.Reader)
	}
	doc["sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(key, c))
	if tamper {
		doc["expires_at"] = expires + 1
	}
	raw, _ := json.Marshal(doc)
	s.docs[host], s.revs[host] = raw, rev
	close(s.wake)
	s.wake = make(chan struct{})
	return rev
}

// Statuses reported so far.
func (s *Server) Statuses() []agent.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]agent.Status{}, s.statuses...)
}

// Enrolled reports whether host has a key.
func (s *Server) Enrolled(host string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hosts[host] != nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/agent/v1/enrol":
		var in struct {
			Host      string `json:"host"`
			Token     string `json:"token"`
			PublicKey string `json:"public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Token != Token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		k, err := generate.ParseKey(in.PublicKey)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.mu.Lock()
		s.hosts[in.Host] = k
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"host": in.Host, "control_plane_key": "ed25519:IGNORED"})
	case "/agent/v1/desired", "/agent/v1/status":
		host, body, ok := s.verify(r)
		s.mu.Lock()
		if s.refuse > 0 {
			s.refuse--
			ok = false
		}
		s.mu.Unlock()
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/agent/v1/status" {
			var st agent.Status
			_ = json.Unmarshal(body, &st)
			s.mu.Lock()
			s.statuses = append(s.statuses, st)
			s.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		have, _ := strconv.ParseInt(r.URL.Query().Get("have"), 10, 64)
		poll := s.Poll
		if poll == 0 {
			poll = 2 * time.Second
		}
		deadline := time.After(poll)
		for {
			s.mu.Lock()
			doc, rev, wake, force := s.docs[host], s.revs[host], s.wake, s.force[host]
			s.mu.Unlock()
			if doc != nil && (rev > have || force) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(doc)
				return
			}
			select {
			case <-wake:
			case <-deadline:
				w.WriteHeader(http.StatusNoContent)
				return
			case <-r.Context().Done():
				return
			}
		}
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) verify(r *http.Request) (string, []byte, bool) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	host, ts, nonce := r.Header.Get("X-Amc-Host"), r.Header.Get("X-Amc-Time"), r.Header.Get("X-Amc-Nonce")
	sig, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Amc-Signature"))
	t, terr := strconv.ParseInt(ts, 10, 64)
	s.mu.Lock()
	k := s.hosts[host]
	s.mu.Unlock()
	if err != nil || terr != nil || k == nil || len(nonce) < 16 {
		return "", nil, false
	}
	if d := time.Now().Unix() - t; d > 120 || d < -120 {
		return "", nil, false
	}
	return host, body, ed25519.Verify(k, agent.SignString(r.Method, r.URL.RequestURI(), ts, nonce, body), sig) &&
		!bytes.Contains([]byte(host), []byte("\n"))
}
