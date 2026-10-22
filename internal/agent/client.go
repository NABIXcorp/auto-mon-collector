package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client talks to the control plane.
type Client struct {
	Base string // agent.url, e.g. https://agent.example.com/agent/
	Host string
	Key  ed25519.PrivateKey
	HTTP *http.Client
	Now  func() time.Time
}

// ErrUnauthorized: the control plane refused (unknown / revoked host, bad signature, clock skew).
var ErrUnauthorized = errors.New("control plane: 401 unauthorized (not enrolled, revoked, or clock skew > 120 s)")

// ErrTooMany: rate limited.
var ErrTooMany = errors.New("control plane: 429 too many requests")

func (c *Client) url(rel string) (*url.URL, error) {
	base, err := url.Parse(strings.TrimRight(c.Base, "/") + "/")
	if err != nil {
		return nil, err
	}
	return base.Parse(rel)
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) do(ctx context.Context, method, rel string, body []byte, sign bool) (*http.Response, error) {
	u, err := c.url(rel)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "amc-agent")
	if sign {
		ts := strconv.FormatInt(c.now().Unix(), 10)
		nonce := Nonce()
		sig := ed25519.Sign(c.Key, SignString(method, u.RequestURI(), ts, nonce, body))
		req.Header.Set("X-Amc-Host", c.Host)
		req.Header.Set("X-Amc-Time", ts)
		req.Header.Set("X-Amc-Nonce", nonce)
		req.Header.Set("X-Amc-Signature", base64.StdEncoding.EncodeToString(sig))
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		resp.Body.Close()
		return nil, ErrUnauthorized
	case http.StatusTooManyRequests:
		resp.Body.Close()
		return nil, ErrTooMany
	}
	return resp, nil
}

// Enrol registers the host's public key with a one-time token.
func (c *Client) Enrol(ctx context.Context, token string) error {
	body, _ := json.Marshal(map[string]string{"host": c.Host, "token": token, "public_key": EncodeKey(c.Key.Public().(ed25519.PublicKey))})
	resp, err := c.do(ctx, http.MethodPost, "v1/enrol", body, false)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enrol: HTTP %d", resp.StatusCode)
	}
	return nil // the control-plane key in the answer is NOT used: the pinned one from the answers counts
}

// Desired long-polls for a document newer than have. nil, nil = nothing newer.
func (c *Client) Desired(ctx context.Context, have int64) ([]byte, error) {
	resp, err := c.do(ctx, http.MethodGet, "v1/desired?have="+strconv.FormatInt(have, 10), nil, true)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		return io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	default:
		return nil, fmt.Errorf("desired: HTTP %d", resp.StatusCode)
	}
}

// Status of one revision.
type Status struct {
	Revision int64             `json:"revision"`
	Result   string            `json:"result"` // applied | rejected | error
	Detail   string            `json:"detail,omitempty"`
	Versions map[string]string `json:"versions,omitempty"`
}

// Inventory (v0.15.0) is sent at start and whenever it changes: the agent's versions, the revision it runs and the
// host's services (<prefix>/inventory.json, written by amc apply / update as root).
type Inventory struct {
	Versions map[string]string `json:"versions,omitempty"`
	Revision int64             `json:"revision"`
	Services json.RawMessage   `json:"inventory"`                 // the file as written; null = missing (installed before v0.15.0)
	Error    string            `json:"inventory_error,omitempty"` // why Services is null
}

// RefusedError: the control plane answered 4xx (not 401 / 429), e.g. 404 = an older control plane without
// the endpoint. Sending the same body again would get the same answer.
type RefusedError struct{ Code int }

func (e *RefusedError) Error() string {
	return fmt.Sprintf("control plane refused it: HTTP %d", e.Code)
}

// SendInventory posts an inventory.
func (c *Client) SendInventory(ctx context.Context, body []byte) error {
	resp, err := c.do(ctx, http.MethodPost, "v1/inventory", body, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode/100 == 2:
		return nil
	case resp.StatusCode/100 == 4:
		return &RefusedError{resp.StatusCode}
	default:
		return fmt.Errorf("inventory: HTTP %d", resp.StatusCode)
	}
}

// Report sends a status.
func (c *Client) Report(ctx context.Context, s Status) error {
	if len(s.Detail) > 500 {
		s.Detail = s.Detail[:500]
	}
	body, _ := json.Marshal(s)
	resp, err := c.do(ctx, http.MethodPost, "v1/status", body, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("status: HTTP %d", resp.StatusCode)
	}
	return nil
}
