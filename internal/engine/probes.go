package engine

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/NABIXcorp/auto-mon-collector/assets"
	"github.com/NABIXcorp/auto-mon-collector/internal/cloudprober"
)

// Cloudprober (v0.12.0): installed only when Desired.Probes is set. Its files: bin/cloudprober,
// config/cloudprober.cfg, config/cloudprober-*.json (targets), systemd/monitoring-cloudprober.service.

var probeTargetRE = regexp.MustCompile(`^cloudprober-[a-z0-9_-]{1,40}\.json$`)

// isProbeFile: a Cloudprober file in config/ (not a collector config: never passed to otelcol validate).
func isProbeFile(rel string) bool {
	return rel == "config/cloudprober.cfg" || (strings.HasPrefix(rel, "config/") && probeTargetRE.MatchString(path.Base(rel)))
}

// staleProbeFiles: installed Cloudprober files that are no longer wanted (probes removed, or a target list gone).
func (e *eng) staleProbeFiles() []string {
	want := map[string]bool{}
	for _, f := range e.files {
		want[f.rel] = true
	}
	var out []string
	entries, _ := os.ReadDir(e.fs(e.pre("config")))
	for _, en := range entries {
		rel := "config/" + en.Name()
		if !en.IsDir() && isProbeFile(rel) && !want[rel] {
			out = append(out, rel)
		}
	}
	unit := "systemd/" + assets.ProbeUnit + ".service"
	if _, err := os.Stat(e.fs(e.pre(unit))); err == nil && !want[unit] {
		out = append(out, unit)
	}
	return out
}

// probeBinary: step 4b, the pinned Cloudprober (only with probes). Like the collector: check mode downloads into
// the temp dir too, so the new config can be tested with --configtest.
func (e *eng) probeBinary(ctx context.Context, tmp string) bool {
	bin := e.pre("bin/cloudprober")
	if e.d.Probes == nil {
		if _, err := os.Stat(e.fs(bin)); err == nil {
			e.r.ok("no probes: %s stays unused (removed by uninstall)", bin)
		}
		return true
	}
	e.r.step("4b. Cloudprober binary %s (%s)", cloudprober.Version, e.o.Arch)
	have := ""
	if _, err := os.Stat(e.fs(bin)); err == nil {
		out, _ := e.o.Runner.Output(nil, e.fs(bin), "--version")
		have = cloudprober.ParseVersion(out)
	}
	if have == cloudprober.Version {
		e.r.ok("%s is %s", bin, have)
		e.probeBin = e.fs(bin)
		return true
	}
	if !e.o.Fetch {
		e.r.fail("%s is %q, not %s (fetch is off)", bin, have, cloudprober.Version)
		return true
	}
	dir := filepath.Join(tmp, "cloudprober")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		e.r.fail("%v", err)
		return true
	}
	got, err := e.o.ProbeFetcher(ctx, e.o.Arch, dir)
	if err != nil {
		e.r.fail("download cloudprober %s: %v", cloudprober.Version, err)
		return true
	}
	e.r.ok("downloaded cloudprober %s, sha256 verified", cloudprober.Version)
	e.probeBin = got
	e.do("install "+bin+" (mode 755, root)", func() error {
		data, err := os.ReadFile(got)
		if err != nil {
			return err
		}
		if _, err := os.Stat(e.fs(bin)); err == nil {
			if err := os.Rename(e.fs(bin), e.fs(bin+".previous")); err != nil {
				return err
			}
			e.probeBinReplaced = true
		}
		if err := e.writeFile(bin, data, 0o755); err != nil {
			return err
		}
		e.probeBin = e.fs(bin)
		return nil
	})
	return true
}

// probeConfigTest: cloudprober --configtest on the NEW config (targets staged next to it).
func (e *eng) probeConfigTest(stage string) bool {
	if e.d.Probes == nil {
		return true
	}
	if e.probeBin == "" {
		e.r.warn("cloudprober --configtest skipped (binary missing)")
		return true
	}
	cfg := strings.ReplaceAll(string(e.d.Probes.Config), ProbePrefix, filepath.ToSlash(stage))
	for n, b := range e.d.Probes.Targets {
		if err := os.WriteFile(filepath.Join(stage, "config", n), b, 0o600); err != nil {
			e.r.fail("stage: %v", err)
			return false
		}
	}
	p := filepath.Join(stage, "config", "cloudprober.cfg")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		e.r.fail("stage: %v", err)
		return false
	}
	out, err := e.o.Runner.Output(nil, e.probeBin, "--configtest", "--config_file="+p)
	if err != nil {
		e.r.fail("cloudprober --configtest failed:")
		lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
		e.r.indent(strings.Join(lines[max(0, len(lines)-10):], "\n"), 10)
		return false
	}
	e.r.ok("cloudprober --configtest: OK")
	return true
}

// dropProbeUnit: probes removed from the answers -> stop + disable the Cloudprober unit and unlink it. Runs in
// apply BEFORE the files are written: `systemctl disable` needs the unit file that is removed with them.
func (e *eng) dropProbeUnit() {
	if e.d.Probes != nil {
		return
	}
	name := assets.ProbeUnit + ".service"
	link := e.fs("/etc/systemd/system/" + name)
	if _, err := os.Lstat(link); err != nil {
		return
	}
	if err := e.o.Runner.Run("systemctl", "disable", "--now", name); err != nil {
		e.r.fail("systemctl disable --now %s: %v", name, err)
		return
	}
	if err := os.Remove(link); err != nil {
		e.r.fail("remove %s: %v", link, err)
		return
	}
	e.st.remove(&e.st.Units, name)
	e.r.ok("no probes: %s stopped, disabled and unlinked", name)
}
