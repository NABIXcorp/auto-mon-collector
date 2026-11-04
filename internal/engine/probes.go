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

// monitoring-prober = Cloudprober (v0.12.0): installed only when Desired.Probes is set. Its files (v0.20.0):
// bin/monitoring-prober, config/prober/prober.cfg + targets-*.json, systemd/monitoring-prober.service. Older layouts
// (removed as stale on the next apply, restored by a rollback): v0.12.0 config/cloudprober.cfg + cloudprober-*.json,
// v0.13.0-v0.19.0 config/cloudprober/cloudprober.cfg + cloudprober-*.json, bin/cloudprober, unit monitoring-cloudprober.

// = generate.ProbeTargetRE / ProbeDir / ProbeConfig (the engine does not import the generator)
var probeTargetRE = regexp.MustCompile(`^targets-[a-z0-9_-]{1,40}\.json$`)

const (
	probeDir    = "config/prober"
	probeConfig = "prober.cfg"
	probeBinRel = "bin/monitoring-prober"
)

// before v0.20.0
var legacyProbeTargetRE = regexp.MustCompile(`^cloudprober-[a-z0-9_-]{1,40}\.json$`)

const (
	legacyProbeDir    = "config/cloudprober"
	legacyProbeBinRel = "bin/cloudprober"
)

// isProbeFile: a prober file (not a collector config: never passed to the collector's validate), old layouts included.
func isProbeFile(rel string) bool {
	if strings.HasPrefix(rel, probeDir+"/") || strings.HasPrefix(rel, legacyProbeDir+"/") {
		return true
	}
	return rel == "config/cloudprober.cfg" || (path.Dir(rel) == "config" && legacyProbeTargetRE.MatchString(path.Base(rel)))
}

// staleProbeFiles: installed prober files that are no longer wanted (probes removed, a target list gone, old layout).
func (e *eng) staleProbeFiles() []string {
	want := map[string]bool{}
	for _, f := range e.files {
		want[f.rel] = true
	}
	var out []string
	for _, dir := range []string{"config", probeDir, legacyProbeDir} {
		entries, _ := os.ReadDir(e.fs(e.pre(dir)))
		for _, en := range entries {
			rel := dir + "/" + en.Name()
			if !en.IsDir() && !strings.HasPrefix(en.Name(), ".") && isProbeFile(rel) && !want[rel] {
				out = append(out, rel)
			}
		}
	}
	unit := "systemd/" + assets.ProbeUnit + ".service"
	if _, err := os.Stat(e.fs(e.pre(unit))); err == nil && !want[unit] {
		out = append(out, unit)
	}
	return out
}

// probeBinary: step 4b, the pinned Cloudprober as bin/monitoring-prober (only with probes). Like the collector: check
// mode downloads into the temp dir too, so the new config can be tested with --configtest. A host on the old layout
// with the right version in bin/cloudprober gets a copy of it (no download).
func (e *eng) probeBinary(ctx context.Context, tmp string) bool {
	bin := e.pre(probeBinRel)
	if e.d.Probes == nil {
		if _, err := os.Stat(e.fs(bin)); err == nil {
			e.r.ok("no probes: %s stays unused (removed by uninstall)", bin)
		}
		return true
	}
	e.r.step("4b. prober binary (Cloudprober %s, %s)", cloudprober.Version, e.o.Arch)
	version := func(p string) string {
		if _, err := os.Stat(e.fs(p)); err != nil {
			return ""
		}
		out, _ := e.o.Runner.Output(nil, e.fs(p), "--version")
		return cloudprober.ParseVersion(out)
	}
	have := version(bin)
	if have == cloudprober.Version {
		e.r.ok("%s is %s", bin, have)
		e.probeBin = e.fs(bin)
		return true
	}
	if old := e.pre(legacyProbeBinRel); have == "" && version(old) == cloudprober.Version {
		e.probeBin = e.fs(old)
		e.do("install "+bin+" (copy of "+old+", mode 755, root)", func() error {
			if err := e.copyBinary(e.fs(old), bin); err != nil {
				return err
			}
			e.probeBin = e.fs(bin)
			return nil
		})
		return true
	}
	if !e.o.Fetch {
		e.r.fail("%s is %q, not %s (fetch is off)", bin, have, cloudprober.Version)
		return true
	}
	dir := filepath.Join(tmp, "prober")
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

// probeConfigTest: monitoring-prober --configtest on the NEW config (targets staged next to it).
func (e *eng) probeConfigTest(stage string) bool {
	if e.d.Probes == nil {
		return true
	}
	if e.probeBin == "" {
		e.r.warn("monitoring-prober --configtest skipped (binary missing)")
		return true
	}
	cfg := strings.ReplaceAll(string(e.d.Probes.Config), ProbePrefix, filepath.ToSlash(stage))
	if err := os.MkdirAll(filepath.Join(stage, filepath.FromSlash(probeDir)), 0o700); err != nil {
		e.r.fail("stage: %v", err)
		return false
	}
	for n, b := range e.d.Probes.Targets {
		if err := os.WriteFile(filepath.Join(stage, filepath.FromSlash(probeDir), n), b, 0o600); err != nil {
			e.r.fail("stage: %v", err)
			return false
		}
	}
	p := filepath.Join(stage, filepath.FromSlash(probeDir), probeConfig)
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		e.r.fail("stage: %v", err)
		return false
	}
	out, err := e.o.Runner.Output(nil, e.probeBin, "--configtest", "--config_file="+p)
	if err != nil {
		e.r.fail("monitoring-prober --configtest failed:")
		lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
		e.r.indent(strings.Join(lines[max(0, len(lines)-10):], "\n"), 10)
		return false
	}
	e.r.ok("monitoring-prober --configtest: OK")
	return true
}

// dropProbeUnit: probes removed from the answers -> stop + disable the prober unit and unlink it. Runs in
// apply BEFORE the files are written: `systemctl disable` needs the unit file that is removed with them.
func (e *eng) dropProbeUnit() {
	if e.d.Probes != nil {
		return
	}
	// `systemctl disable` removes a linked unit's link itself; dropUnit removes it only when it is still there
	e.dropUnit(assets.ProbeUnit+".service", "no probes")
}
