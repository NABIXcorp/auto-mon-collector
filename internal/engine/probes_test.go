package engine

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/internal/cloudprober"
	"github.com/NABIXcorp/auto-mon-collector/internal/collector"
)

func withProbes(ping bool) Desired {
	d := desired()
	d.Probes = &Probes{
		Config:  []byte("host: \"127.0.0.1\"\nprobe { targets { file_targets { file_path: \"@PREFIX@/config/cloudprober-tcp.json\" } } }\n"),
		Targets: map[string][]byte{"cloudprober-tcp.json": []byte(`{"resource":[]}` + "\n")},
		Ping:    ping,
	}
	return d
}

func TestProbesCheckModeDownloadsAndTestsConfig(t *testing.T) {
	h := smokeHost(t)
	r := &fakeRunner{version: collector.Version, readable: true}
	res, out := runWith(t, h, r, false, false, true, false, withProbes(false))
	if res.Failures != 0 || res.Applied {
		t.Fatalf("check failed:\n%s", out)
	}
	for _, want := range []string{"4b. Cloudprober binary " + cloudprober.Version, "downloaded cloudprober", "cloudprober --configtest: OK",
		"NEW    config/cloudprober.cfg", "NEW    config/cloudprober-tcp.json", "NEW    systemd/monitoring-cloudprober.service"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, c := range r.cmds {
		if strings.Contains(c, "validate") && strings.Contains(c, "cloudprober") {
			t.Errorf("a Cloudprober file was given to otelcol validate: %s", c)
		}
	}
	if _, err := os.Stat(filepath.Join(h.root, "opt/monitoring/bin/cloudprober")); err == nil {
		t.Error("check mode installed the Cloudprober binary")
	}
}

func TestProbesConfigTestFailureStops(t *testing.T) {
	h := smokeHost(t)
	r := &fakeRunner{version: collector.Version, readable: true, configtest: errors.New("exit 1")}
	res, out := runWith(t, h, r, false, false, true, false, withProbes(false))
	if res.Failures == 0 || !strings.Contains(out, "cloudprober --configtest failed") || !strings.Contains(out, "unknown field") {
		t.Errorf("configtest failure not reported:\n%s", out)
	}
}

func TestNoProbesNoCloudprober(t *testing.T) {
	h := smokeHost(t)
	r := &fakeRunner{version: collector.Version, readable: true}
	_, out := runWith(t, h, r, false, false, true, false, desired())
	if strings.Contains(out, "loudprober") {
		t.Errorf("no probes, but Cloudprober shows up:\n%s", out)
	}
}

func TestProbesApplyThenRemove(t *testing.T) {
	needSymlinks(t)
	h := smokeHost(t)
	r := &fakeRunner{version: collector.Version, readable: true}
	res, out := runWith(t, h, r, true, true, true, false, withProbes(true))
	if res.Failures != 0 {
		t.Fatalf("apply failed:\n%s", out)
	}
	if got := h.read("/opt/monitoring/config/cloudprober.cfg"); !strings.Contains(got, `"/opt/monitoring/config/cloudprober-tcp.json"`) {
		t.Errorf("prefix not filled in:\n%s", got)
	}
	if h.read("/opt/monitoring/bin/cloudprober") != "PROBER" {
		t.Error("cloudprober binary not installed")
	}
	if u := h.read("/opt/monitoring/systemd/monitoring-cloudprober.service"); !strings.Contains(u, "AmbientCapabilities=CAP_NET_RAW") {
		t.Errorf("ping unit without CAP_NET_RAW:\n%s", u)
	}
	if !r.has("systemctl restart monitoring-otelcol.service") || !r.has("monitoring-cloudprober.service") {
		t.Errorf("cloudprober unit not managed: %v", r.cmds)
	}
	if !strings.Contains(h.read("/opt/monitoring/"+StateFile), "monitoring-cloudprober.service") {
		t.Error("cloudprober unit not recorded for uninstall")
	}

	// probes removed from the answers: unit stopped + unlinked, files removed, nothing else touched
	r2 := &fakeRunner{version: collector.Version, readable: true, probeVersion: "v" + cloudprober.Version}
	res, out = runWith(t, h, r2, true, true, false, false, desired())
	if res.Failures != 0 {
		t.Fatalf("second apply failed:\n%s", out)
	}
	for _, want := range []string{"REMOVE config/cloudprober.cfg", "REMOVE config/cloudprober-tcp.json",
		"REMOVE systemd/monitoring-cloudprober.service", "stopped, disabled and unlinked"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if !r2.has("systemctl disable --now monitoring-cloudprober.service") {
		t.Errorf("unit not disabled: %v", r2.cmds)
	}
	if _, err := os.Lstat(filepath.Join(h.root, "etc/systemd/system/monitoring-cloudprober.service")); err == nil {
		t.Error("unit link left behind")
	}
	if strings.Contains(h.read("/opt/monitoring/"+StateFile), "monitoring-cloudprober") {
		t.Error("state still lists the cloudprober unit")
	}
	for _, c := range r2.cmds {
		if strings.HasPrefix(c, "systemctl restart") && strings.Contains(c, "cloudprober") {
			t.Errorf("removed unit restarted: %s", c)
		}
	}
}

func TestProbesInstalledVersionIsKept(t *testing.T) {
	h := smokeHost(t)
	h.write("/opt/monitoring/bin/cloudprober", "INSTALLED", 0o755)
	r := &fakeRunner{version: collector.Version, readable: true, probeVersion: "v" + cloudprober.Version}
	_, out := runWith(t, h, r, false, false, false, false, withProbes(false))
	if !strings.Contains(out, "/opt/monitoring/bin/cloudprober is "+cloudprober.Version) || strings.Contains(out, "downloaded cloudprober") {
		t.Errorf("installed pinned version not recognised:\n%s", out)
	}
}
