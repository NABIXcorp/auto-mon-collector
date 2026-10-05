// Package collector pins the otelcol-contrib release amc installs and downloads it safely: the tarball is
// checked against the pinned SHA-256 before anything is unpacked, and only the otelcol-contrib binary is
// taken out of it.
package collector

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Version is the pinned otelcol-contrib release. Change = new amc release.
const Version = "0.160.0"

// Asset is one release tarball.
type Asset struct {
	URL    string
	SHA256 string
}

// Checksums from the GitHub release API ("digest" of each asset), checked 2026-10-01.
var assets = map[string]Asset{
	"amd64": {
		URL:    "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.160.0/otelcol-contrib_0.160.0_linux_amd64.tar.gz",
		SHA256: "7bb60c584c241c86261c2b8697cd3725dd8c56691f5ad5d98454eaa005b47b0c",
	},
	"arm64": {
		URL:    "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.160.0/otelcol-contrib_0.160.0_linux_arm64.tar.gz",
		SHA256: "bff414e6a287309dfd0c51350c1e13c96c4ab807127b4320bd684f605e781326",
	},
}

// For returns the pinned asset for a Go architecture name (amd64, arm64).
func For(arch string) (Asset, error) {
	a, ok := assets[arch]
	if !ok {
		return Asset{}, fmt.Errorf("unsupported CPU architecture %q (supported: amd64, arm64)", arch)
	}
	return a, nil
}

var versionRE = regexp.MustCompile(`\b(\d+\.\d+\.\d+)\b`)

// ParseVersion extracts x.y.z from `otelcol-contrib --version` output ("" if none).
func ParseVersion(out []byte) string {
	if m := versionRE.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return ""
}

// ErrChecksum means the download does not match the pinned SHA-256: nothing was unpacked.
var ErrChecksum = errors.New("checksum mismatch: nothing unpacked")

// Fetch downloads a into dir and returns the path of the extracted otelcol-contrib binary.
func Fetch(ctx context.Context, a Asset, dir string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: HTTP %d", a.URL, resp.StatusCode)
	}
	tarball := filepath.Join(dir, "otelcol-contrib.tar.gz")
	if err := saveVerified(resp.Body, tarball, a.SHA256); err != nil {
		return "", err
	}
	return ExtractBinary(tarball, dir)
}

// saveVerified writes r to path and checks its SHA-256; on mismatch the file is removed.
func saveVerified(r io.Reader, path, want string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		os.Remove(path)
		return fmt.Errorf("%w (got %s, want %s)", ErrChecksum, got, want)
	}
	return nil
}

// ExtractBinary takes only the regular file "otelcol-contrib" out of a verified tarball.
func ExtractBinary(tarball, dir string) (string, error) {
	f, err := os.Open(tarball)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return "", errors.New("otelcol-contrib not found in the tarball")
		}
		if err != nil {
			return "", err
		}
		if h.Name != "otelcol-contrib" || h.Typeflag != tar.TypeReg {
			continue // never follow paths or links from the archive
		}
		out := filepath.Join(dir, "otelcol-contrib")
		w, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(w, io.LimitReader(tr, 1<<30)); err != nil {
			w.Close()
			return "", err
		}
		return out, w.Close()
	}
}
