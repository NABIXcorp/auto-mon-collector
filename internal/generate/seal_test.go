package generate

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shared test vector (the console seals the same way): host private key 32 x 0x11, ephemeral private key
// 32 x 0x22, nonce 12 x 0x33, key "oracle_password", plain "s3cret-Pass". Checked independently with Node crypto.
const (
	vecHostPub = "e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM="
	vecBlob    = "D6poTtKIZ7l/Smot7l34zpdOdrcBjj8iocTPJnhXDyAzMzMzMzMzMzMzMzNJ/g1mQfEobPpZrVGRzqN8W7YKq9Z64853PPc="
)

func TestSealVector(t *testing.T) {
	hostPriv := bytes.Repeat([]byte{0x11}, 32)
	hp, _ := ecdh.X25519().NewPrivateKey(hostPriv)
	if got := base64.StdEncoding.EncodeToString(hp.PublicKey().Bytes()); got != vecHostPub {
		t.Fatalf("host public key %s", got)
	}
	r := bytes.NewReader(append(bytes.Repeat([]byte{0x22}, 32), bytes.Repeat([]byte{0x33}, 12)...))
	blob, err := sealFrom(r, hp.PublicKey().Bytes(), "oracle_password", []byte("s3cret-Pass"))
	if err != nil || blob != vecBlob {
		t.Fatalf("seal: %v\n got %s\nwant %s", err, blob, vecBlob)
	}
	plain, err := Open(hostPriv, "oracle_password", vecBlob)
	if err != nil || string(plain) != "s3cret-Pass" {
		t.Fatalf("open: %v %q", err, plain)
	}
}

func TestSealOpen(t *testing.T) {
	host, _ := ecdh.X25519().GenerateKey(rand.Reader)
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	blob, err := Seal(host.PublicKey().Bytes(), "redis_password", []byte("pa ss"))
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := Seal(host.PublicKey().Bytes(), "redis_password", []byte("pa ss")); again == blob {
		t.Error("two seals of the same value are equal (no fresh ephemeral key / nonce)")
	}
	if p, err := Open(host.Bytes(), "redis_password", blob); err != nil || string(p) != "pa ss" {
		t.Fatalf("open: %v %q", err, p)
	}
	if _, err := Open(host.Bytes(), "oracle_password", blob); err == nil {
		t.Error("a Redis blob opened as the Oracle password (the AAD binds the slot)")
	}
	if _, err := Open(other.Bytes(), "redis_password", blob); err == nil {
		t.Error("opened with another host key")
	}
	raw, _ := base64.StdEncoding.DecodeString(blob)
	raw[len(raw)-1] ^= 1
	if _, err := Open(host.Bytes(), "redis_password", base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Error("a changed blob opened")
	}
	for _, bad := range []string{"", "!!", base64.StdEncoding.EncodeToString(make([]byte, 60))} {
		if _, err := Open(host.Bytes(), "redis_password", bad); err == nil {
			t.Errorf("%q opened", bad)
		}
	}
	for _, p := range []string{"", strings.Repeat("x", 257), "a\nb", "a'b", "a\rb", "a\x00b"} {
		if CheckPlainPassword([]byte(p)) == nil {
			t.Errorf("plain %q accepted", p)
		}
	}
	if err := CheckPlainPassword([]byte(strings.Repeat("x", 256))); err != nil {
		t.Error(err)
	}
	if err := CheckPlainPassword([]byte("a'b")); err == nil || strings.Contains(err.Error(), "a'b") {
		t.Errorf("the error holds the value: %v", err)
	}
}

func TestSealKeyAndPasswordState(t *testing.T) {
	pre := t.TempDir()
	if msg, err := SealHousekeeping(pre); err != nil || msg != "" {
		t.Fatalf("not installed: %q %v", msg, err)
	}
	if err := os.MkdirAll(filepath.Join(pre, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pre, "secrets", "collector.env"), []byte("OO_AUTH='x'\nREDIS_PASSWORD='r'\nORACLE_MON_PASSWORD=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	msg, err := SealHousekeeping(pre)
	if err != nil || !strings.Contains(msg, "key pair made") {
		t.Fatalf("first: %q %v", msg, err)
	}
	pub, err := LoadSealPub(pre)
	priv, perr := LoadSealPriv(pre)
	if err != nil || perr != nil || base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()) != pub {
		t.Fatalf("pair: %v %v", err, perr)
	}
	if msg, err := SealHousekeeping(pre); err != nil || msg != "" {
		t.Errorf("second run made a new pair: %q %v", msg, err)
	}
	if again, _ := LoadSealPub(pre); again != pub {
		t.Error("the key changed")
	}
	// a lost public file is written again from the private key
	os.Remove(filepath.Join(pre, filepath.FromSlash(SealPubFile)))
	if _, err := EnsureSealKey(pre); err != nil {
		t.Fatal(err)
	}
	if again, _ := LoadSealPub(pre); again != pub {
		t.Error("the public file was not restored")
	}
	st, err := LoadPasswordState(pre)
	if err != nil || st["redis_password"] != "set" || st["oracle_password"] != "not set" || len(st) != 2 {
		t.Errorf("state: %v %v", st, err)
	}
	b, _ := os.ReadFile(filepath.Join(pre, filepath.FromSlash(PasswordStateFile)))
	if strings.Contains(string(b), "'r'") || strings.Contains(string(b), `"r"`) {
		t.Errorf("the state file holds a value: %s", b)
	}
	// a sealed value round trip with the host's own files
	blob, _ := Seal(priv.PublicKey().Bytes(), "oracle_password", []byte("x"))
	if p, err := Open(priv.Bytes(), "oracle_password", blob); err != nil || string(p) != "x" {
		t.Errorf("open with the host key: %v", err)
	}
}

func TestCheckSettingsPasswords(t *testing.T) {
	a := settingsAnswers(t, "  settings:\n    allow: [oracle_password, rescan]\n")
	host, _ := ecdh.X25519().GenerateKey(rand.Reader)
	blob, _ := Seal(host.PublicKey().Bytes(), "oracle_password", []byte("x"))
	cases := []struct {
		name string
		pw   map[string]SealedPassword
		want string
	}{
		{"ok", map[string]SealedPassword{"oracle_password": {ID: "pw_1-a", Sealed: blob}}, ""},
		{"unknown key", map[string]SealedPassword{"postgres_password": {ID: "a", Sealed: blob}}, `unknown password key "postgres_password"`},
		{"not consented", map[string]SealedPassword{"redis_password": {ID: "a", Sealed: blob}}, "redis_password is not in answers.yaml agent.settings.allow"},
		{"bad id", map[string]SealedPassword{"oracle_password": {ID: "a b", Sealed: blob}}, "id must be"},
		{"long id", map[string]SealedPassword{"oracle_password": {ID: strings.Repeat("a", 65), Sealed: blob}}, "id must be"},
		{"malformed blob", map[string]SealedPassword{"oracle_password": {ID: "a", Sealed: "eA=="}}, "sealed value malformed"},
	}
	for _, c := range cases {
		err := CheckSettings(SettingsOverlay{Passwords: c.pw}, a)
		if (c.want == "" && err != nil) || (c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want))) {
			t.Errorf("%s: %v (want %q)", c.name, err, c.want)
		}
	}
	// passwords are never pinned
	if strings.Contains(strings.Join(a.Agent.Pinned(), ","), "password") {
		t.Errorf("pinned: %v", a.Agent.Pinned())
	}
	// the document carries the blob, the file only the ids
	var ov SettingsOverlay
	doc := `{"revision":2,"set":{},"passwords":{"oracle_password":{"id":"pw1","sealed":"` + blob + `"}}}`
	if err := json.Unmarshal([]byte(doc), &ov); err != nil || ov.Passwords["oracle_password"].ID != "pw1" || ov.Empty() {
		t.Fatalf("document: %v %+v", err, ov)
	}
	ov.PasswordIDs = map[string]string{"oracle_password": "pw1"}
	b, err := MarshalSettingsOverlay(ov)
	if err != nil || strings.Contains(string(b), blob) || !strings.Contains(string(b), "oracle_password: pw1") {
		t.Fatalf("file: %v\n%s", err, b)
	}
	p := filepath.Join(t.TempDir(), "settings.cp.yaml")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSettingsOverlay(p)
	if err != nil || got.PasswordIDs["oracle_password"] != "pw1" || got.Passwords != nil || got.String() != "passwords oracle_password" {
		t.Errorf("load: %v %+v %q", err, got, got.String())
	}
	if err := os.WriteFile(p, []byte("revision: 1\nset: {}\npasswords:\n  oracle_password: \"a b\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSettingsOverlay(p); err == nil {
		t.Error("a bad id in the file was accepted")
	}
}
