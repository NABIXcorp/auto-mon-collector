package generate

import (
	"strings"
	"testing"
)

const noiseOverlay = `processors:
  filter/traces_noise:
    error_mode: ignore
    trace_conditions:
      - IsMatch(span.attributes["db.statement"], "LongPoll[.]Wait$$")
service:
  pipelines:
    traces:
      processors: [memory_limiter, resource_detection, filter/traces_noise, tail_sampling, batch]
`

func TestCheckOverlay(t *testing.T) {
	if err := CheckSite(map[string]string{"cp-traces-noise.yaml": noiseOverlay}); err != nil {
		t.Fatalf("the pilot overlay: %v", err)
	}
	if err := CheckSite(map[string]string{}); err != nil {
		t.Fatalf("an empty set (remove the control plane's overlays): %v", err)
	}
	bad := []struct{ name, yaml, want string }{
		{"receiver", "receivers:\n  file_log/x:\n    include: [/etc/shadow]\n", `"receivers" is not allowed`},
		{"exporter", "exporters:\n  otlp_http/x:\n    endpoint: https://evil.example\n", `"exporters" is not allowed`},
		{"extension", "extensions:\n  pprof: {}\n", `"extensions" is not allowed`},
		{"connector", "connectors:\n  signal_to_metrics: {}\n", `"connectors" is not allowed`},
		{"telemetry", "service:\n  telemetry:\n    logs: {level: debug}\n", "service.telemetry is not allowed"},
		{"pipeline receivers", "service:\n  pipelines:\n    logs:\n      receivers: [file_log]\n", "logs.receivers is not allowed"},
		{"pipeline exporters", "service:\n  pipelines:\n    logs:\n      exporters: [debug]\n", "logs.exporters is not allowed"},
		{"processor outside the catalog", "processors:\n  batch/x: {}\n", "not in the overlay catalog"},
		{"memory_limiter", "processors:\n  memory_limiter/x: {check_interval: 1s}\n", "not in the overlay catalog"},
		{"file expansion", "processors:\n  transform/x:\n    log_statements: ['set(log.body, \"${file:/etc/shadow}\")']\n", "expansion"},
		{"env expansion", "processors:\n  transform/x:\n    log_statements: ['set(log.body, \"${env:OO_AUTH}\")']\n", "expansion"},
		{"bare $", "processors:\n  filter/x:\n    error_mode: $MODE\n", "expansion"},
		{"anchor", "processors:\n  filter/a: &a {error_mode: ignore}\n  filter/b: *a\n", "anchors"},
		{"merge key", "processors:\n  filter/a:\n    <<: {error_mode: ignore}\n", "merge"},
		{"tag", "processors:\n  filter/a: !!map {error_mode: ignore}\n", "tag"},
		{"two documents", "processors: {}\n---\nreceivers: {}\n", "one YAML document"},
		{"list top level", "- a\n", "mapping"},
		{"not YAML", "processors: [\n", "YAML"},
		{"processor list item not a name", "service:\n  pipelines:\n    logs:\n      processors: [{a: b}]\n", "names only"},
	}
	for _, c := range bad {
		err := CheckOverlay([]byte(c.yaml))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	names := []string{"10-x.yaml", "cp-../x.yaml", "cp-a/b.yaml", "cp-A.yaml", "cp-x.yml", ".cp-x.yaml", "cp-.yaml"}
	for _, n := range names {
		if err := CheckSite(map[string]string{n: "processors: {}\n"}); err == nil {
			t.Errorf("name %q accepted", n)
		}
	}
	many := map[string]string{}
	for i := 0; i < SiteMaxFiles+1; i++ {
		many["cp-"+string(rune('a'+i))+".yaml"] = "processors: {}\n"
	}
	if err := CheckSite(many); err == nil {
		t.Error("too many files accepted")
	}
	if err := CheckSite(map[string]string{"cp-big.yaml": "# " + strings.Repeat("x", SiteMaxFile) + "\n"}); err == nil {
		t.Error("a too large file accepted")
	}
}
