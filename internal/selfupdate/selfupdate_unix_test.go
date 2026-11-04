//go:build unix

package selfupdate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/lockfile"
)

// The agent owns <prefix>/agent: a link there must not make root read (and echo) another file.
func TestSelfUpdateRequestLinkRefused(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t, "  update:\n    allow: true\n")
			e.request(nil, nil)
			req := filepath.Join(e.prefix, filepath.FromSlash(agent.UpdateRequestFile))
			real := filepath.Join(e.prefix, "real.json")
			if err := os.Rename(req, real); err != nil {
				t.Fatal(err)
			}
			link := os.Symlink
			if kind == "hardlink" {
				link = os.Link
			}
			if err := link(real, req); err != nil {
				t.Fatal(err)
			}
			if res := e.run(); res.Result != "refused" || !strings.Contains(res.Detail, "request:") {
				t.Fatalf("%+v", res)
			}
			if e.read("bin/amc") != oldBin {
				t.Error("bin/amc changed")
			}
		})
	}
}

func TestSelfUpdateAnswersMustBeRootOnly(t *testing.T) {
	e := newEnv(t, "  update:\n    allow: true\n")
	e.request(nil, nil)
	if err := os.Chmod(filepath.Join(e.prefix, "answers.yaml"), 0o666); err != nil {
		t.Fatal(err)
	}
	if res := e.run(); res.Result != "refused" || !strings.Contains(res.Detail, "writable by group or others") {
		t.Fatalf("%+v", res)
	}
}

func TestSelfUpdateWaitsForNoOtherAmc(t *testing.T) {
	e := newEnv(t, "  update:\n    allow: true\n")
	e.request(nil, nil)
	l, err := lockfile.Acquire(e.prefix) // an `amc apply` is running
	if err != nil {
		t.Fatal(err)
	}
	res := e.run()
	l.Release()
	if res.Result != "refused" || !strings.Contains(res.Detail, "another monitoring-agent") {
		t.Fatalf("%+v", res)
	}
	if e.read("bin/amc") != oldBin || e.requests.Load() != 0 {
		t.Error("something changed while another amc held the lock")
	}
	if r := e.result(); r.ID != "u-0123456789" || r.Result != "refused" {
		t.Errorf("result file: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(e.prefix, RecordFile)); err == nil {
		t.Error("a request refused for the lock counts as handled (it could never be retried)")
	}
	if res := e.run(); res.Result != "ok" {
		t.Errorf("after the other amc finished: %+v", res)
	}
}
