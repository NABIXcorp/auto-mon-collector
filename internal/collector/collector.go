// Package collector gets the collector monitoring-agent installs: monitoring-collector, our own OpenTelemetry Collector build
// (collector/ in this repository, phases D1-D3). It comes from the SAME signed release as monitoring-agent: SHA256SUMS is checked
// against the release key embedded in monitoring-agent before the large download, the binary against its line in SHA256SUMS
// while it is written. Nothing else is trusted (no URL, no checksum from answers or from the network).
package collector

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/selfupdate"
	"github.com/NABIXcorp/auto-mon-collector/keys"
)

// Name is the binary (<prefix>/bin/monitoring-collector) and the release asset prefix (<Name>-linux-<arch>).
const Name = "monitoring-collector"

// CoreVersion is the OpenTelemetry Collector core inside (collector/builder-config.yaml). `--version` prints it and
// does NOT change when only our receivers change: "up to date" is decided by sha256, never by the version.
const CoreVersion = "0.160.0"

// Asset is a pinned download (URL + SHA-256), used for Cloudprober.
type Asset struct {
	URL    string
	SHA256 string
}

// ErrChecksum means a download does not match its expected SHA-256: nothing was installed.
var ErrChecksum = errors.New("checksum mismatch: nothing unpacked")

// AssetName is the release asset for a Go architecture name.
func AssetName(arch string) (string, error) {
	if arch != "amd64" && arch != "arm64" {
		return "", fmt.Errorf("unsupported CPU architecture %q (supported: amd64, arm64)", arch)
	}
	return Name + "-linux-" + arch, nil
}

// Source gives the expected sha256 of the collector and downloads it (engine.Options.Collector; tests fake it).
type Source interface {
	// Sum is the sha256 of the collector for arch that the release lists (signature checked).
	Sum(ctx context.Context, arch string) ([32]byte, error)
	// Fetch downloads the collector into dir and returns its path; the file's sha256 equals want.
	Fetch(ctx context.Context, arch string, want [32]byte, dir string) (string, error)
}

// releaseBase is the only place a release comes from (like selfupdate): <base><version>/<asset>.
const releaseBase = "https://github.com/NABIXcorp/auto-mon-collector/releases/download/"

const (
	maxSums   = 64 << 10
	maxSig    = 1 << 10
	maxBinary = 512 << 20 // ~218 MB today
)

var tagRE = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// Release is the collector of monitoring-agent release Version (e.g. v0.19.0). Base, Key and HTTP are for tests.
type Release struct {
	Version string
	Base    string // default releaseBase
	// Mirror (v0.24.0, answers release_mirror): tried first; any error -> Base. Same signature check.
	Mirror string
	Log    io.Writer // where a mirror fallback is reported (nil = nowhere)
	Key    []byte    // default keys.ReleasePub
	HTTP   *http.Client
	// Dir: keep the download here and reuse it while its sha256 matches (`monitoring-agent update` plans and then applies:
	// one download, not two). "" = into the directory Fetch is given. The caller removes Dir.
	Dir string

	sums []byte // verified SHA256SUMS (after Sum)
}

func (r *Release) defaults() {
	if r.Base == "" {
		r.Base = releaseBase
	}
	if r.Key == nil {
		r.Key = keys.ReleasePub
	}
	if r.HTTP == nil {
		r.HTTP = &http.Client{Timeout: 15 * time.Minute}
	}
}

// Sum downloads SHA256SUMS + SHA256SUMS.sig of the release, checks the signature and returns the collector's line.
func (r *Release) Sum(ctx context.Context, arch string) ([32]byte, error) {
	r.defaults()
	name, err := AssetName(arch)
	if err != nil {
		return [32]byte{}, err
	}
	if !tagRE.MatchString(r.Version) {
		return [32]byte{}, fmt.Errorf("monitoring-agent %q is not a release build: no collector to download (use --collector-file)", r.Version)
	}
	if r.sums == nil {
		key, err := selfupdate.ParseReleaseKey(r.Key)
		if err != nil {
			return [32]byte{}, err
		}
		sums, err := r.get(ctx, "SHA256SUMS", maxSums)
		if err != nil {
			return [32]byte{}, err
		}
		sig, err := r.get(ctx, "SHA256SUMS.sig", maxSig)
		if err != nil {
			return [32]byte{}, err
		}
		if err := selfupdate.VerifySums(key, sums, sig); err != nil {
			return [32]byte{}, err
		}
		r.sums = sums
	}
	return selfupdate.SumFor(r.sums, name)
}

// Fetch streams the collector into dir/monitoring-collector and checks its sha256 (the file is removed on mismatch).
func (r *Release) Fetch(ctx context.Context, arch string, want [32]byte, dir string) (string, error) {
	r.defaults()
	name, err := AssetName(arch)
	if err != nil {
		return "", err
	}
	if r.Dir != "" {
		dir = r.Dir
		if s, err := FileSum(filepath.Join(dir, Name)); err == nil && s == want {
			return filepath.Join(dir, Name), nil
		}
	}
	resp, err := r.open(ctx, name, maxBinary)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	out := filepath.Join(dir, Name)
	if err := SaveVerified(io.LimitReader(resp.Body, maxBinary), out, want, 0o755); err != nil {
		return "", err
	}
	return out, nil
}

func (r *Release) open(ctx context.Context, name string, limit int64) (*http.Response, error) {
	if r.Mirror != "" {
		resp, err := r.openAt(ctx, r.Mirror, name, limit)
		if err == nil {
			return resp, nil
		}
		if r.Log != nil {
			fmt.Fprintf(r.Log, "release mirror: %v; using %s\n", err, r.Base)
		}
	}
	return r.openAt(ctx, r.Base, name, limit)
}

func (r *Release) openAt(ctx context.Context, base, name string, limit int64) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+r.Version+"/"+name, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "monitoring-agent")
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", name, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("download %s: HTTP %d", name, resp.StatusCode)
	}
	if resp.ContentLength > limit {
		resp.Body.Close()
		return nil, fmt.Errorf("download %s: too large (%d bytes, limit %d)", name, resp.ContentLength, limit)
	}
	return resp, nil
}

func (r *Release) get(ctx context.Context, name string, limit int64) ([]byte, error) {
	resp, err := r.open(ctx, name, limit)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", name, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("download %s: too large", name)
	}
	return b, nil
}

// SaveVerified writes rd to path (mode) and checks its sha256; on any error or mismatch the file is removed.
func SaveVerified(rd io.Reader, path string, want [32]byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), rd)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && [32]byte(h.Sum(nil)) != want {
		err = fmt.Errorf("%w (%s)", ErrChecksum, filepath.Base(path))
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}

// FileSum is the sha256 of a file.
func FileSum(path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, err
	}
	return [32]byte(h.Sum(nil)), nil
}
