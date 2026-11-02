package selfupdate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/keys"
)

// testKey: a throwaway ECDSA key and its PEM public key (never the release key).
func testKey(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// signSums is what `openssl dgst -sha256 -sign` writes: DER ECDSA over sha256(data).
func signSums(t *testing.T, k *ecdsa.PrivateKey, sums []byte) []byte {
	t.Helper()
	h := sha256.Sum256(sums)
	sig, err := ecdsa.SignASN1(rand.Reader, k, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func sumsFor(files map[string][]byte) []byte {
	var b strings.Builder
	for _, n := range []string{"amc-linux-amd64", "amc-linux-arm64", "get.sh"} {
		if f, ok := files[n]; ok {
			h := sha256.Sum256(f)
			b.WriteString(hex.EncodeToString(h[:]) + "  " + n + "\n") // sha256sum text mode: two spaces
		}
	}
	return []byte(b.String())
}

func TestEmbeddedReleaseKey(t *testing.T) {
	if _, err := ParseReleaseKey(keys.ReleasePub); err != nil {
		t.Fatalf("the embedded keys/amc-release.pub: %v", err)
	}
	if _, err := ParseReleaseKey(releaseKey); err != nil {
		t.Fatal(err)
	}
}

func TestParseReleaseKeyRefusesOthers(t *testing.T) {
	_, p384 := testKey(t, elliptic.P384())
	_, p256 := testKey(t, elliptic.P256())
	for name, b := range map[string][]byte{
		"P-384":        p384,
		"empty":        nil,
		"not PEM":      []byte("hello"),
		"two blocks":   append(append([]byte{}, p256...), p256...),
		"private type": []byte(strings.Replace(string(p256), "PUBLIC KEY", "EC PRIVATE KEY", 2)),
	} {
		if _, err := ParseReleaseKey(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestVerifyAsset(t *testing.T) {
	k, pub := testKey(t, elliptic.P256())
	other, _ := testKey(t, elliptic.P256())
	key, err := ParseReleaseKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	bin := []byte("NEW BINARY")
	sums := sumsFor(map[string][]byte{"amc-linux-amd64": bin, "amc-linux-arm64": []byte("ARM"), "get.sh": []byte("sh")})
	sig := signSums(t, k, sums)
	if err := VerifyAsset(key, sums, sig, "amc-linux-amd64", bin); err != nil {
		t.Fatalf("good release: %v", err)
	}
	flip := func(b []byte, i int) []byte { c := append([]byte{}, b...); c[i] ^= 1; return c }
	cases := map[string]struct {
		sums, sig, bin []byte
		name, want     string
	}{
		"bad signature":       {sums, flip(sig, len(sig)-1), bin, "amc-linux-amd64", "not signed"},
		"other key":           {sums, signSums(t, other, sums), bin, "amc-linux-amd64", "not signed"},
		"sums changed":        {append(append([]byte{}, sums...), ' '), sig, bin, "amc-linux-amd64", "not signed"},
		"binary changed":      {sums, sig, flip(bin, 0), "amc-linux-amd64", "checksum mismatch"},
		"binary truncated":    {sums, sig, bin[:4], "amc-linux-amd64", "checksum mismatch"},
		"signature truncated": {sums, sig[:len(sig)/2], bin, "amc-linux-amd64", "not signed"},
		"signature empty":     {sums, nil, bin, "amc-linux-amd64", "signature missing"},
		"signature oversize":  {sums, make([]byte, maxSig+1), bin, "amc-linux-amd64", "signature missing"},
		"asset not listed":    {sums, sig, bin, "amc-linux-riscv64", "lists no"},
	}
	for name, c := range cases {
		err := VerifyAsset(key, c.sums, c.sig, c.name, c.bin)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", name, err, c.want)
		}
	}
}

func TestSumFor(t *testing.T) {
	h := strings.Repeat("ab", 32)
	if _, err := SumFor([]byte(h+" *amc-linux-amd64\n"), "amc-linux-amd64"); err != nil {
		t.Errorf("binary mode line: %v", err)
	}
	for name, s := range map[string]string{
		"twice":     h + "  amc-linux-amd64\n" + h + "  amc-linux-amd64\n",
		"malformed": h + "  amc-linux-amd64\ngarbage\n",
		"upper hex": strings.ToUpper(h) + "  amc-linux-amd64\n",
		"short":     h[:60] + "  amc-linux-amd64\n",
		"prefix":    h + "  x/amc-linux-amd64\n",
	} {
		if _, err := SumFor([]byte(s), "amc-linux-amd64"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
