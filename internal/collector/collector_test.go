package collector

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func tarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	return b.Bytes()
}

func serve(t *testing.T, body []byte) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(body) }))
	t.Cleanup(srv.Close)
	return srv.URL + "/otelcol.tar.gz"
}

func TestFetchVerifiesThenExtractsOnlyTheBinary(t *testing.T) {
	body := tarball(t, map[string]string{"otelcol-contrib": "BINARY", "README.md": "x", "../evil": "x"})
	sum := sha256.Sum256(body)
	dir := t.TempDir()
	bin, err := Fetch(context.Background(), Asset{URL: serve(t, body), SHA256: hex.EncodeToString(sum[:])}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(bin); string(got) != "BINARY" {
		t.Errorf("binary content = %q", got)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "evil")); err == nil {
		t.Error("path outside the target dir was written")
	}
}

func TestFetchRefusesWrongChecksum(t *testing.T) {
	body := tarball(t, map[string]string{"otelcol-contrib": "TAMPERED"})
	dir := t.TempDir()
	_, err := Fetch(context.Background(), Asset{URL: serve(t, body), SHA256: Version /* surely wrong */}, dir)
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("err = %v, want ErrChecksum", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("files left after a checksum mismatch: %v", entries)
	}
}

func TestPinned(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		a, err := For(arch)
		if err != nil || len(a.SHA256) != 64 || !bytes.Contains([]byte(a.URL), []byte(Version)) {
			t.Errorf("%s: %+v %v", arch, a, err)
		}
	}
	if _, err := For("riscv64"); err == nil {
		t.Error("unsupported arch must fail")
	}
	if v := ParseVersion([]byte("otelcol-contrib version 0.160.0\n")); v != "0.160.0" {
		t.Errorf("ParseVersion = %q", v)
	}
}
