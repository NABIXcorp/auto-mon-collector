package cloudprober

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
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/internal/collector"
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
	return srv.URL + "/cloudprober.tar.gz"
}

func TestFetchVerifiesThenExtractsOnlyTheBinary(t *testing.T) {
	inner := binaryIn("amd64")
	body := tarball(t, map[string]string{inner: "BINARY", "cloudprober": "WRONG PLACE", "../evil": "x"})
	sum := sha256.Sum256(body)
	dir := t.TempDir()
	bin, err := fetch(context.Background(), collector.Asset{URL: serve(t, body), SHA256: hex.EncodeToString(sum[:])}, inner, dir)
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
	body := tarball(t, map[string]string{binaryIn("amd64"): "TAMPERED"})
	dir := t.TempDir()
	_, err := fetch(context.Background(), collector.Asset{URL: serve(t, body), SHA256: Version}, binaryIn("amd64"), dir)
	if !errors.Is(err, collector.ErrChecksum) {
		t.Fatalf("err = %v, want ErrChecksum", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("files left after a checksum mismatch: %v", entries)
	}
}

func TestPinned(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		a, err := For(arch)
		if err != nil || len(a.SHA256) != 64 || !strings.Contains(a.URL, "v"+Version) ||
			!strings.Contains(a.URL, strings.TrimSuffix(strings.TrimPrefix(binaryIn(arch), "cloudprober-v"+Version+"-"), "/cloudprober")) {
			t.Errorf("%s: %+v %v", arch, a, err)
		}
	}
	if _, err := For("riscv64"); err == nil {
		t.Error("unsupported arch must fail")
	}
	if v := ParseVersion([]byte("v0.14.6\n")); v != Version {
		t.Errorf("ParseVersion = %q", v)
	}
}
