package collector

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// release serves a fake signed release v0.19.0 with one collector binary and returns a Release for it.
func release(t *testing.T, body string, tamper bool) (*Release, [32]byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	sum := sha256.Sum256([]byte(body))
	sums := "1111111111111111111111111111111111111111111111111111111111111111  monitoring-agent-linux-amd64\n" +
		hex.EncodeToString(sum[:]) + "  monitoring-collector-linux-amd64\n"
	h := sha256.Sum256([]byte(sums))
	sig, err := ecdsa.SignASN1(rand.Reader, k, h[:])
	if err != nil {
		t.Fatal(err)
	}
	served := body
	if tamper {
		served = body + "x"
	}
	files := map[string]string{"/v0.19.0/SHA256SUMS": sums, "/v0.19.0/SHA256SUMS.sig": string(sig),
		"/v0.19.0/monitoring-collector-linux-amd64": served}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(b))
	}))
	t.Cleanup(srv.Close)
	return &Release{Version: "v0.19.0", Base: srv.URL + "/", Key: pub}, sum
}

func TestReleaseSumAndFetch(t *testing.T) {
	r, want := release(t, "collector binary", false)
	got, err := r.Sum(context.Background(), "amd64")
	if err != nil || got != want {
		t.Fatalf("Sum = %x, %v", got, err)
	}
	dir := t.TempDir()
	p, err := r.Fetch(context.Background(), "amd64", got, dir)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := FileSum(p); s != want {
		t.Fatal("fetched file has another sum")
	}
	if _, err := r.Sum(context.Background(), "arm64"); err == nil || !strings.Contains(err.Error(), "lists no") {
		t.Fatalf("arm64 not in SHA256SUMS: %v", err)
	}
}

func TestFetchTamperedIsRemoved(t *testing.T) {
	r, want := release(t, "collector binary", true)
	dir := t.TempDir()
	if _, err := r.Fetch(context.Background(), "amd64", want, dir); !errors.Is(err, ErrChecksum) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, Name)); !os.IsNotExist(err) {
		t.Fatal("a file that failed the check must not stay")
	}
}

func TestSumRefusesWrongKeyAndDevBuild(t *testing.T) {
	r, _ := release(t, "collector binary", false)
	other, _ := release(t, "x", false)
	r.Key = other.Key // signed by another key
	if _, err := r.Sum(context.Background(), "amd64"); err == nil {
		t.Fatal("a signature by another key must fail")
	}
	dev := &Release{Version: "dev"}
	if _, err := dev.Sum(context.Background(), "amd64"); err == nil || !strings.Contains(err.Error(), "--collector-file") {
		t.Fatalf("dev build: %v", err)
	}
	if _, err := AssetName("386"); err == nil {
		t.Fatal("386 must be refused")
	}
}

func TestFetchReusesTheDownloadInDir(t *testing.T) {
	r, want := release(t, "collector binary", false)
	r.Dir = t.TempDir()
	p1, err := r.Fetch(context.Background(), "amd64", want, t.TempDir())
	if err != nil || filepath.Dir(p1) != r.Dir {
		t.Fatalf("%s %v", p1, err)
	}
	r.Base = "http://127.0.0.1:1/" // no server: the second call must not download
	if p2, err := r.Fetch(context.Background(), "amd64", want, t.TempDir()); err != nil || p2 != p1 {
		t.Fatalf("second fetch: %s %v", p2, err)
	}
}

func TestReleaseMirrorFirstThenBase(t *testing.T) {
	r, want := release(t, "collector binary", false)
	var hits int
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		http.Error(w, "warming", http.StatusServiceUnavailable)
	}))
	t.Cleanup(dead.Close)
	var log strings.Builder
	r.Mirror, r.Log = dead.URL+"/", &log
	got, err := r.Sum(context.Background(), "amd64")
	if err != nil || got != want || hits == 0 || !strings.Contains(log.String(), "release mirror") {
		t.Fatalf("Sum = %x, %v; mirror hits %d; log %q", got, err, hits, log.String())
	}
	// a working mirror: the base is not asked
	good := r.Base
	r.Mirror, r.Base, r.sums = good, dead.URL+"/", nil
	if got, err := r.Sum(context.Background(), "amd64"); err != nil || got != want {
		t.Fatalf("Sum via mirror = %x, %v", got, err)
	}
}
