package procsreceiver

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

const fixtures = "testdata/proc"

func TestSnapshot(t *testing.T) {
	s, err := snapshot(fixtures)
	require.NoError(t, err)
	require.Len(t, s, 3) // 1, 42, 100; "notapid" is skipped
	require.Equal(t, proc{pid: 100, uid: "1001", comm: "my prog) x", ticks: 300, start: 99000, rssKB: 2000}, s[100])
	require.Equal(t, uint64(10000), s[42].ticks)
	require.Equal(t, int64(1000000), s[42].rssKB)
	up, err := uptimeSeconds(fixtures)
	require.NoError(t, err)
	require.Equal(t, 1000.5, up)
}

func TestSnapshotMissing(t *testing.T) {
	_, err := snapshot("testdata/nope")
	require.Error(t, err)
}

// second snapshot: java used 15 s of CPU in 15 s (100 %), systemd 0.15 s (1 %), pid 100 started 10 s ago with 3 s of CPU (30 %).
func later(t *testing.T) (a, b map[int]proc) {
	a, err := snapshot(fixtures)
	require.NoError(t, err)
	b = map[int]proc{}
	for k, v := range a {
		b[k] = v
	}
	j := b[42]
	j.ticks += 1500
	b[42] = j
	s := b[1]
	s.ticks += 15
	b[1] = s
	delete(a, 100)
	return a, b
}

func TestPick(t *testing.T) {
	a, b := later(t)
	rows := pick(a, b, 15, 1000.5, 2)
	got := map[int]string{}
	for _, r := range rows {
		got[r.pid] = r.top
	}
	require.Equal(t, map[int]string{1: "rss", 42: "cpu,rss", 100: "cpu"}, got)
	for _, r := range rows {
		switch r.pid {
		case 1:
			require.InDelta(t, 1.0, r.cpu, 0.001)
		case 42:
			require.InDelta(t, 100.0, r.cpu, 0.001)
			require.Equal(t, int64(950), r.etime)
		case 100:
			require.InDelta(t, 30.0, r.cpu, 0.001)
			require.Equal(t, int64(10), r.etime)
		}
	}
	require.Len(t, pick(a, b, 15, 1000.5, 1), 1) // java is top by both
}

func TestPickPidReused(t *testing.T) {
	a, b := later(t)
	j := b[42]
	j.start = 99500 // same pid, other process: started 5.5 s ago
	b[42] = j
	for _, r := range pick(a, b, 15, 1000.5, 3) {
		if r.pid == 42 {
			require.InDelta(t, float64(j.ticks)/userHZ*100/5, r.cpu, 0.001) // lifetime CPU, not a diff to the old process
		}
	}
}

func newTest(t *testing.T) *pr {
	r, err := createLogs(context.Background(), receivertest.NewNopSettings(typeStr), createDefaultConfig(), consumertest.NewNop())
	require.NoError(t, err)
	p := r.(*pr)
	p.lookup = func(uid string) string { return map[string]string{"0": "root", "987": "otelcol-contrib"}[uid] }
	return p
}

// Golden-style check on the full record shape (what reaches OpenObserve), same as file_log/procs today.
func TestRecordShape(t *testing.T) {
	a, b := later(t)
	ld := newTest(t).build(pick(a, b, 15, 1000.5, 2), time.Date(2026, 11, 2, 10, 0, 7, 500, time.UTC))
	lrs := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	require.Equal(t, 3, lrs.Len())
	lr := lrs.At(1) // pid 42 (rows are in pid order)
	require.Equal(t, `{"time":"2026-11-02T10:00:07Z","pid":42,"user":"otelcol-contrib","comm":"java","rss_kb":1000000,"cpu_pct":100.0,"etime_s":950,"top":"cpu,rss"}`,
		lr.Body().Str())
	require.Equal(t, map[string]any{"log_type": "processes", "pid": 42.0, "user": "otelcol-contrib", "comm": "java",
		"rss_kb": 1000000.0, "cpu_pct": 100.0, "etime_s": 950.0, "top": "cpu,rss"}, lr.Attributes().AsRaw())
	require.Equal(t, int64(1793613607000000000), int64(lr.Timestamp()))
	require.Contains(t, lrs.At(2).Body().Str(), `"comm":"my prog) x"`)
}

func TestConfigValidate(t *testing.T) {
	c := createDefaultConfig()
	require.NoError(t, c.Validate())
	c.Window = c.CollectionInterval
	require.Error(t, c.Validate())
	c = createDefaultConfig()
	c.Top = 0
	require.Error(t, c.Validate())
}

func TestStartEmits(t *testing.T) {
	sink := new(consumertest.LogsSink)
	cfg := createDefaultConfig()
	cfg.ProcPath = fixtures
	cfg.CollectionInterval = 40 * time.Millisecond
	cfg.Window = 10 * time.Millisecond
	r, err := createLogs(context.Background(), receivertest.NewNopSettings(typeStr), cfg, sink)
	require.NoError(t, err)
	require.NoError(t, r.Start(context.Background(), componenttest.NewNopHost()))
	require.Eventually(t, func() bool { return len(sink.AllLogs()) >= 2 }, 3*time.Second, 10*time.Millisecond)
	require.NoError(t, r.Shutdown(context.Background()))
	require.Positive(t, sink.AllLogs()[0].LogRecordCount())
}
