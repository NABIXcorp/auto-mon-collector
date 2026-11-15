package engine

import "testing"

func TestBadLogLine(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		// collector console log: judged by the level field only
		{"2026-01-01T00:00:00.000Z\tinfo\tjournaldreceiver/input.go:1\tJournalctl command\t{\"args\": \"--priority warning\"}", false},
		{"2026-01-01T00:00:00.000Z\twarn\texporter/x.go:1\tsending queue is full", true},
		{"2026-01-01T00:00:00.000Z\terror\texporter/x.go:1\tExporting failed", true},
		{"2026-01-01T00:00:00.000Z\tinfo\tservice.go:1\tEverything is ready, error_mode=ignore", false},
		// logfmt / JSON level
		{`time=2026-01-01T00:00:00Z level=INFO msg="retry on warning"`, false},
		{`time=2026-01-01T00:00:00Z level=WARN msg="slow"`, true},
		{`{"level":"error","msg":"x"}`, true},
		{`{"level":"info","msg":"no errors"}`, false},
		// no level field: word check (systemd lines, plain prints)
		{"Fatal error: cannot open config", true},
		{"Started monitoring-collector.service.", false},
		// probe lines stay out
		{"2026-01-01T00:00:00.000Z\twarn\toracledb\tfailed to probe RDS/OCI hosting", false},
		{"", false},
	}
	for _, c := range cases {
		if got := badLogLine(c.line); got != c.want {
			t.Errorf("badLogLine(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}
