// Package cloudprober pins the Cloudprober release amc installs for the probes (v0.12.0) and downloads it the
// same safe way as the collector: the tarball is checked against the pinned SHA-256 before anything is
// unpacked, and only the cloudprober binary is taken out of it.
package cloudprober

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

	"github.com/NABIXcorp/auto-mon-collector/internal/collector"
)

// Version is the pinned Cloudprober release (github.com/cloudprober/cloudprober, Apache-2.0). Change = new amc release.
const Version = "0.14.6"

// Checksums from the GitHub release API ("digest" of each asset), checked 2026-10-21.
var assets = map[string]collector.Asset{
	"amd64": {
		URL:    "https://github.com/cloudprober/cloudprober/releases/download/v0.14.6/cloudprober-v0.14.6-linux-x86_64.tar.gz",
		SHA256: "29fb6ede16f732f3ca16a49650219a9e96e5ee3aba329648182a0757f8773a7a",
	},
	"arm64": {
		URL:    "https://github.com/cloudprober/cloudprober/releases/download/v0.14.6/cloudprober-v0.14.6-linux-arm64.tar.gz",
		SHA256: "1407fd39333039402bff65efb8e2c5348f2e4c578954e8a95480cc1169854472",
	},
}

// binaryIn is the path of the binary inside the tarball of arch.
func binaryIn(arch string) string {
	a := map[string]string{"amd64": "x86_64", "arm64": "arm64"}[arch]
	return "cloudprober-v" + Version + "-linux-" + a + "/cloudprober"
}

// For returns the pinned asset for a Go architecture name (amd64, arm64).
func For(arch string) (collector.Asset, error) {
	a, ok := assets[arch]
	if !ok {
		return collector.Asset{}, fmt.Errorf("cloudprober: unsupported CPU architecture %q (supported: amd64, arm64)", arch)
	}
	return a, nil
}

var versionRE = regexp.MustCompile(`\bv?(\d+\.\d+\.\d+)\b`)

// ParseVersion extracts x.y.z from `cloudprober --version` output ("v0.14.6"; "" if none).
func ParseVersion(out []byte) string {
	if m := versionRE.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return ""
}

// Fetch downloads the asset of arch into dir and returns the path of the extracted cloudprober binary.
func Fetch(ctx context.Context, arch, dir string) (string, error) {
	a, err := For(arch)
	if err != nil {
		return "", err
	}
	return fetch(ctx, a, binaryIn(arch), dir)
}

func fetch(ctx context.Context, a collector.Asset, inner, dir string) (string, error) {
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
	tarball := filepath.Join(dir, "cloudprober.tar.gz")
	if err := saveVerified(resp.Body, tarball, a.SHA256); err != nil {
		return "", err
	}
	return ExtractBinary(tarball, inner, dir)
}

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
		return fmt.Errorf("%w (got %s, want %s)", collector.ErrChecksum, got, want)
	}
	return nil
}

// ExtractBinary takes only the regular file `name` out of a verified tarball (never paths or links from it).
func ExtractBinary(tarball, name, dir string) (string, error) {
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
			return "", errors.New(name + " not found in the tarball")
		}
		if err != nil {
			return "", err
		}
		if h.Name != name || h.Typeflag != tar.TypeReg {
			continue
		}
		out := filepath.Join(dir, "cloudprober")
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
