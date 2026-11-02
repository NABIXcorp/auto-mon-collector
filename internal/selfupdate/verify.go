package selfupdate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ParseReleaseKey reads a PEM "PUBLIC KEY" (PKIX) that must be ECDSA P-256 (keys/amc-release.pub).
func ParseReleaseKey(b []byte) (*ecdsa.PublicKey, error) {
	blk, rest := pem.Decode(b)
	if blk == nil || blk.Type != "PUBLIC KEY" || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("release key: one PEM block \"PUBLIC KEY\" expected")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("release key: %w", err)
	}
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("release key: not an ECDSA P-256 key")
	}
	return ek, nil
}

// VerifySums checks SHA256SUMS.sig: an ASN.1 DER ECDSA signature over sha256(SHA256SUMS), exactly what
// `openssl dgst -sha256 -sign KEY -out SHA256SUMS.sig SHA256SUMS` writes (release.yml) and get.sh verifies.
func VerifySums(key *ecdsa.PublicKey, sums, sig []byte) error {
	if len(sig) == 0 || len(sig) > maxSig {
		return errors.New("signature missing or malformed")
	}
	h := sha256.Sum256(sums)
	if !ecdsa.VerifyASN1(key, h[:], sig) {
		return errors.New("SHA256SUMS is not signed by the auto-mon-collector release key")
	}
	return nil
}

// sumLineRE: one sha256sum line, text (" ") or binary ("*") mode.
var sumLineRE = regexp.MustCompile(`^([0-9a-f]{64}) [ *](\S+)$`)

// SumFor returns the sha256 SHA256SUMS lists for name. Exactly one line for name; every line must be well formed.
func SumFor(sums []byte, name string) ([32]byte, error) {
	var out [32]byte
	found := 0
	for _, l := range strings.Split(strings.TrimRight(string(sums), "\n"), "\n") {
		m := sumLineRE.FindStringSubmatch(l)
		if m == nil {
			return out, errors.New("SHA256SUMS: malformed line")
		}
		if m[2] != name {
			continue
		}
		b, _ := hex.DecodeString(m[1])
		copy(out[:], b)
		found++
	}
	switch found {
	case 0:
		return out, fmt.Errorf("SHA256SUMS lists no %s", name)
	case 1:
		return out, nil
	default:
		return out, fmt.Errorf("SHA256SUMS lists %s more than once", name)
	}
}

// VerifyAsset: signature first, then the asset's sha256 against the signed list.
func VerifyAsset(key *ecdsa.PublicKey, sums, sig []byte, name string, asset []byte) error {
	if err := VerifySums(key, sums, sig); err != nil {
		return err
	}
	want, err := SumFor(sums, name)
	if err != nil {
		return err
	}
	if sha256.Sum256(asset) != want {
		return fmt.Errorf("checksum mismatch for %s", name)
	}
	return nil
}
