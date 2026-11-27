package generate

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/NABIXcorp/auto-mon-collector/internal/envfile"
)

// Sealed passwords (v0.37.0, docs/design.md "Sealed passwords from the console"). Root makes an X25519 key pair
// (SealKeyFile root 600, SealPubFile 644); the inventory reports the public key; the console seals a password to it
// and sends the blob in the signed document; only root can open it and writes the value into secrets/collector.env.
// The agent user, the console's database and every log hold only the sealed blob, never the value.
//
//	blob = base64(eph_pub[32] || nonce[12] || AES-256-GCM(k, plain, aad = "amc-seal-v1|" + key))
//	k    = SHA-256("amc-seal-v1" || X25519(eph_priv, host_pub) || eph_pub || host_pub)
//
// key = the consent key (PasswordKeys, e.g. "oracle_password"): the AAD binds a blob to its slot.

// PasswordKeys: the consent keys for passwords (sorted, a FIXED list); PasswordEnv: the collector.env key of each.
var (
	PasswordKeys = []string{"oracle_password", "redis_password"}
	PasswordEnv  = map[string]string{"oracle_password": "ORACLE_MON_PASSWORD", "redis_password": "REDIS_PASSWORD"}
)

const (
	// SealKeyFile: the host's private key (raw 32 bytes, standard base64; root 600)
	SealKeyFile = "secrets/settings.key"
	// SealPubFile: its public key (standard base64; 644): the agent reports it as settings_seal_key
	SealPubFile = "config/settings.pub"
	// PasswordStateFile: {"<key>": "set" | "not set"} for every PasswordKeys key, written by root (644) after
	// apply / update / install and after a settings job; the agent cannot read collector.env, it reports this file
	PasswordStateFile = "config/settings-passwords.json"

	sealLabel = "amc-seal-v1"
	sealOver  = 32 + 12 + 16 // eph_pub + nonce + GCM tag
	maxPlain  = 256
)

// SealedPassword is one password in the signed document: the console's id and the sealed blob.
type SealedPassword struct {
	ID     string `json:"id"`
	Sealed string `json:"sealed"`
}

var passwordIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidPasswordID: 1..64 of [A-Za-z0-9_-].
func ValidPasswordID(id string) bool { return passwordIDRE.MatchString(id) }

// CheckPlainPassword: 1..256 bytes, no NUL / CR / LF / ' (an env file line). The error never holds the value.
func CheckPlainPassword(p []byte) error {
	if len(p) < 1 || len(p) > maxPlain {
		return fmt.Errorf("a password is 1..%d bytes (got %d)", maxPlain, len(p))
	}
	if bytes.ContainsAny(p, "\x00\r\n'") {
		return errors.New("a password may not hold NUL, CR, LF or '")
	}
	return nil
}

// sealKey: the AES key from the shared secret and both public keys.
func sealKey(shared, ephPub, hostPub []byte) []byte {
	h := sha256.New()
	h.Write([]byte(sealLabel))
	h.Write(shared)
	h.Write(ephPub)
	h.Write(hostPub)
	return h.Sum(nil)
}

func sealAAD(key string) []byte { return []byte(sealLabel + "|" + key) }

// Seal seals plain for the host public key hostPub (32 bytes) under the slot key. A fresh ephemeral key and nonce
// each time (crypto/rand).
func Seal(hostPub []byte, key string, plain []byte) (string, error) {
	return sealFrom(rand.Reader, hostPub, key, plain)
}

// sealFrom: Seal with the ephemeral private key (32 bytes) and then the nonce (12 bytes) read from r (test vectors).
func sealFrom(r io.Reader, hostPub []byte, key string, plain []byte) (string, error) {
	hp, err := ecdh.X25519().NewPublicKey(hostPub)
	if err != nil {
		return "", fmt.Errorf("seal: host key: %w", err)
	}
	var eb [32]byte
	if _, err := io.ReadFull(r, eb[:]); err != nil {
		return "", err
	}
	eph, err := ecdh.X25519().NewPrivateKey(eb[:])
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return "", err
	}
	shared, err := eph.ECDH(hp)
	if err != nil {
		return "", err
	}
	ephPub := eph.PublicKey().Bytes()
	gcm, err := newGCM(sealKey(shared, ephPub, hostPub))
	if err != nil {
		return "", err
	}
	out := append(append(slices.Clone(ephPub), nonce...), gcm.Seal(nil, nonce, plain, sealAAD(key))...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// Open opens a blob sealed for the host private key hostPriv (32 bytes) under the slot key. A blob for another
// slot, another host key or a changed blob fails (without saying more).
func Open(hostPriv []byte, key, blob string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(blob)
	if err != nil || len(b) <= sealOver {
		return nil, errors.New("sealed value malformed")
	}
	priv, err := ecdh.X25519().NewPrivateKey(hostPriv)
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	ephPub, nonce, ct := b[:32], b[32:44], b[44:]
	ep, err := ecdh.X25519().NewPublicKey(ephPub)
	if err != nil {
		return nil, errors.New("sealed value malformed")
	}
	shared, err := priv.ECDH(ep)
	if err != nil {
		return nil, errors.New("sealed value malformed")
	}
	gcm, err := newGCM(sealKey(shared, ephPub, priv.PublicKey().Bytes()))
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ct, sealAAD(key))
	if err != nil {
		return nil, errors.New("cannot open the sealed value (sealed for another host key or another slot: send it again)")
	}
	return plain, nil
}

func newGCM(k []byte) (cipher.AEAD, error) {
	c, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(c)
}

// checkSealedShape: what the agent can check without the private key.
func checkSealedShape(blob string) error {
	b, err := base64.StdEncoding.DecodeString(blob)
	if err != nil || len(b) <= sealOver || len(b) > sealOver+maxPlain {
		return errors.New("sealed value malformed (standard base64 of 32 + 12 + 16 + 1..256 bytes)")
	}
	return nil
}

// ---- the host key pair

// EnsureSealKey (root): makes the key pair when the private key is missing (a new public file too), and rewrites
// the public file when it is missing or does not match. created = a new pair.
func EnsureSealKey(prefix string) (created bool, err error) {
	kp := filepath.Join(prefix, filepath.FromSlash(SealKeyFile))
	priv, err := LoadSealPriv(prefix)
	if errors.Is(err, os.ErrNotExist) {
		if priv, err = ecdh.X25519().GenerateKey(rand.Reader); err != nil {
			return false, err
		}
		if err := writeFileAtomic(kp, []byte(base64.StdEncoding.EncodeToString(priv.Bytes())+"\n"), 0o600); err != nil {
			return false, err
		}
		created = true
	} else if err != nil {
		return false, err
	}
	pub := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	if cur, err := LoadSealPub(prefix); err == nil && cur == pub && !created {
		return false, nil
	}
	return created, writeFileAtomic(filepath.Join(prefix, filepath.FromSlash(SealPubFile)), []byte(pub+"\n"), 0o644)
}

// LoadSealPriv (root) reads the private key (os.ErrNotExist = none).
func LoadSealPriv(prefix string) (*ecdh.PrivateKey, error) {
	b, err := os.ReadFile(filepath.Join(prefix, filepath.FromSlash(SealKeyFile)))
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("%s: not a base64 32-byte key (remove it: the next update makes a new pair, then send the passwords again)", SealKeyFile)
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

// LoadSealPub reads the public key as written (standard base64 of 32 bytes; os.ErrNotExist = none).
func LoadSealPub(prefix string) (string, error) {
	b, err := os.ReadFile(filepath.Join(prefix, filepath.FromSlash(SealPubFile)))
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if raw, err := base64.StdEncoding.DecodeString(s); err != nil || len(raw) != 32 {
		return "", fmt.Errorf("%s: not a base64 32-byte key", SealPubFile)
	}
	return s, nil
}

// ---- set / not set

// PasswordState (root): "set" when collector.env has a non-empty line for the key, else "not set", for every
// PasswordKeys key. A missing collector.env = all "not set".
func PasswordState(prefix string) (map[string]string, error) {
	out := map[string]string{}
	env := map[string]string{}
	b, err := os.ReadFile(filepath.Join(prefix, "secrets", "collector.env"))
	if err == nil {
		if env, err = envfile.Parse(b); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, k := range PasswordKeys {
		out[k] = "not set"
		if env[PasswordEnv[k]] != "" {
			out[k] = "set"
		}
	}
	return out, nil
}

// WritePasswordState (root) writes PasswordStateFile (644) from collector.env. Never a value.
func WritePasswordState(prefix string) error {
	st, err := PasswordState(prefix)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(st)
	return writeFileAtomic(filepath.Join(prefix, filepath.FromSlash(PasswordStateFile)), append(b, '\n'), 0o644)
}

// LoadPasswordState reads PasswordStateFile (the agent); missing = nil, nil. Only known keys and values pass.
func LoadPasswordState(prefix string) (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join(prefix, filepath.FromSlash(PasswordStateFile)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st map[string]string
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("%s: %w", PasswordStateFile, err)
	}
	out := map[string]string{}
	for _, k := range PasswordKeys {
		if v := st[k]; v == "set" || v == "not set" {
			out[k] = v
		}
	}
	return out, nil
}

// SealHousekeeping (root, after apply / update / install of a host with an agent section): the key pair when
// missing, then the set / not set file. The message is for the operator (never a value).
func SealHousekeeping(prefix string) (string, error) {
	if _, err := os.Stat(filepath.Join(prefix, "secrets")); err != nil {
		return "", nil // not installed here (yet)
	}
	created, err := EnsureSealKey(prefix)
	if err != nil {
		return "", fmt.Errorf("settings key pair: %w", err)
	}
	if err := WritePasswordState(prefix); err != nil {
		return "", fmt.Errorf("%s: %w", PasswordStateFile, err)
	}
	if created {
		return fmt.Sprintf("settings key pair made (%s root 600, %s): the console can send sealed passwords", SealKeyFile, SealPubFile), nil
	}
	return "", nil
}

// writeFileAtomic: a new temp file in the same folder (O_EXCL), mode, owner root when we are root, rename.
func writeFileAtomic(p string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), "."+filepath.Base(p)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, mode)
	}
	if err == nil && os.Geteuid() == 0 {
		err = os.Lchown(tmp, 0, 0)
	}
	if err == nil {
		err = os.Rename(tmp, p)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}
