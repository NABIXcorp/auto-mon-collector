// Package keys embeds the release public key, so `monitoring-agent self-update` checks a download with exactly the key that
// get.sh checks (scripts/render-get.sh renders the same file into get.sh).
package keys

import _ "embed"

// ReleasePub is release.pub (amc-release.pub before v0.20.0): the ECDSA P-256 public key (PEM, "PUBLIC KEY") whose private half signs
// SHA256SUMS of every release (secret AMC_SIGNING_KEY, release.yml).
//
//go:embed release.pub
var ReleasePub []byte
