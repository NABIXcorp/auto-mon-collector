// Package agent is `monitoring-agent agent` (v0.13.0): it fetches a signed list of probes from a control plane and applies it
// to the local Cloudprober. Remote = data only: the agent never runs commands or writes paths it gets from the
// control plane. It checks every list with the control-plane key pinned in the answers (never one sent by the
// server), the host's allowlist and the monitoring-agent probe rules, then `cloudprober --configtest`. See docs/design.md,
// section 17.
//
// Wire format (the control plane must match it exactly):
//   - keys: Ed25519, "ed25519:" + standard base64 (with padding) of the 32-byte public key.
//   - POST <url>v1/enrol {"host","token","public_key"}: no signature (one-time token).
//   - every other request has the headers X-Mon-Host, X-Mon-Time (unix seconds), X-Mon-Nonce (16-64 chars
//     [A-Za-z0-9_-]) and X-Mon-Signature: standard base64 Ed25519 (host key) over
//     METHOD "\n" REQUEST-URI "\n" time "\n" nonce "\n" hex(sha256(body)), REQUEST-URI = path + "?" + query.
//   - GET <url>v1/desired?have=N: 200 = a newer signed document, 204 = nothing newer (long poll, <= 60 s).
//   - POST <url>v1/status {"revision","result":"applied|rejected|error","detail","versions"}.
//   - document {"host","revision","issued_at","expires_at","probes":{...},"sig"}, times in unix seconds; sig =
//     standard base64 Ed25519 (control-plane key) over the canonical JSON of the document without "sig".
//   - v0.16.0: the document may carry "update":{"version":"vX.Y.Z","id":"..."} (remote monitoring-agent update, signed like the
//     rest); the status may carry "update":{"id","result","detail","from","to"} and the inventory "update_allowed".
//     An agent before v0.16.0 rejects a document with "update" (unknown field): send it only to v0.16.0+ agents.
//   - v0.23.0: the document may carry "site":{"revision":N,"files":{"cp-<name>.yaml":"<yaml>"}} (the control plane's
//     complete collector overlay set, inside generate.CheckSite); the status may carry "site":{"revision","result",
//     "detail"} and the inventory "site_allowed". Send it only to agents that report site_allowed (v0.23.0+), and
//     never together with a new update request (the update goes first, the set waits for a later document).
package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

// CanonicalJSON: the received object parsed as generic JSON, the keys in drop removed (top level), written again
// with object keys sorted by byte value, no whitespace, no HTML escaping, numbers exactly as received.
// Identical to the control plane's (shared test vectors: testdata/agent/canonical.json).
func CanonicalJSON(doc []byte, drop ...string) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after the JSON value")
	}
	if m, ok := v.(map[string]any); ok {
		for _, k := range drop {
			delete(m, k)
		}
	}
	var b bytes.Buffer
	if err := writeCanonical(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeCanonical(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := writeCanonical(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case string:
		writeString(b, x)
	case json.Number:
		b.WriteString(x.String())
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case nil:
		b.WriteString("null")
	default:
		return fmt.Errorf("unexpected JSON value %T", v)
	}
	return nil
}

func writeString(b *bytes.Buffer, s string) {
	var t bytes.Buffer
	enc := json.NewEncoder(&t)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	b.Write(bytes.TrimRight(t.Bytes(), "\n"))
}

// EncodeKey writes a public key as "ed25519:<base64>".
func EncodeKey(p ed25519.PublicKey) string { return "ed25519:" + base64.StdEncoding.EncodeToString(p) }

// Doc is the control plane's desired state for one host.
type Doc struct {
	Host     string          `json:"host"`
	Revision int64           `json:"revision"`
	Issued   int64           `json:"issued_at"`
	Expires  int64           `json:"expires_at"`
	Probes   generate.Probes `json:"probes"`
	Update   *UpdateRequest  `json:"update,omitempty"` // v0.16.0: remote monitoring-agent update (nil = none)
	Site     *SiteRequest    `json:"site,omitempty"`   // v0.23.0: the control plane's collector overlays (nil = none)
	Sig      string          `json:"sig"`
}

// UpdateRequest (v0.16.0): "update monitoring-agent to this signed release". The only argument is the version: the download
// URL, the release key and the commands are compiled into monitoring-agent (internal/selfupdate), never sent.
type UpdateRequest struct {
	Version string `json:"version"` // release tag, e.g. v0.16.0
	ID      string `json:"id"`      // chosen by the control plane, reported back with the result
}

// SiteRequest (v0.23.0): the control plane's complete overlay set for this host (file name -> YAML; names start
// with generate.SitePrefix, contents inside generate.CheckSite). An empty set removes the control plane's overlays.
// Revision counts the set (a new set = a higher revision); it is reported back with root's result.
type SiteRequest struct {
	Revision int64             `json:"revision"`
	Files    map[string]string `json:"files"`
}

// updateIDRE: an update id (it goes into files and status lines, never into a path).
var updateIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// ValidUpdateID reports whether id has the allowed form.
func ValidUpdateID(id string) bool { return updateIDRE.MatchString(id) }

// Reject is a list the agent refuses (reported as "rejected", the last good list stays).
type Reject struct{ Reason string }

func (r *Reject) Error() string { return r.Reason }

func reject(format string, a ...any) error { return &Reject{fmt.Sprintf(format, a...)} }

// Verify checks a received document: signature (pinned key), host, revision, expiry, probe rules, allowlist.
func Verify(raw []byte, cpKey ed25519.PublicKey, host string, applied int64, now time.Time, allow generate.Allow) (Doc, error) {
	d, err := VerifySigned(raw, cpKey, host, applied, now)
	if err != nil {
		return d, err
	}
	if err := d.Probes.Validate(); err != nil {
		return d, reject("%v", err)
	}
	if err := d.Probes.CheckAllow(allow); err != nil {
		return d, reject("outside the allowlist: %v", err)
	}
	return d, nil
}

// VerifySigned checks what every document needs, whatever it asks for: signature (pinned key), host, revision >
// applied, not expired. `monitoring-agent self-update` (root) uses it to re-verify an update request the agent saved.
func VerifySigned(raw []byte, cpKey ed25519.PublicKey, host string, applied int64, now time.Time) (Doc, error) {
	var d Doc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return d, reject("not a probe document: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(d.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return d, reject("signature missing or malformed")
	}
	msg, err := CanonicalJSON(raw, "sig")
	if err != nil {
		return d, reject("canonical JSON: %v", err)
	}
	if !ed25519.Verify(cpKey, msg, sig) {
		return d, reject("bad signature (not signed by the pinned control-plane key)")
	}
	switch {
	case d.Host != host:
		return d, reject("document is for host %q, this is %q", d.Host, host)
	case d.Revision <= applied:
		return d, reject("revision %d is not newer than the applied %d", d.Revision, applied)
	case now.Unix() >= d.Expires:
		return d, reject("document expired at %s", time.Unix(d.Expires, 0).UTC().Format(time.RFC3339))
	}
	return d, nil
}

// SignString is what the host key signs for one request.
func SignString(method, requestURI, ts, nonce string, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte(method + "\n" + requestURI + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(h[:]))
}

// Nonce: 24 random bytes, base64url without padding (32 chars).
func Nonce() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
