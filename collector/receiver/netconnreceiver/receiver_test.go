package netconnreceiver

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

func newTest(t *testing.T, proc string) *nc {
	cfg := createDefaultConfig()
	cfg.ProcPath = proc
	r, err := createLogs(context.Background(), receivertest.NewNopSettings(typeStr), cfg, consumertest.NewNop())
	require.NoError(t, err)
	n := r.(*nc)
	n.now = func() time.Time { return time.Date(2026, 11, 2, 10, 0, 7, 500, time.UTC) }
	return n
}

func TestCounts(t *testing.T) {
	ld, err := newTest(t, "testdata/proc").collect()
	require.NoError(t, err)
	lrs := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	require.Equal(t, 6, lrs.Len()) // 3 ports x in/out
	want := map[string][4]float64{ // established, close_wait, time_wait, other
		"1521/in": {3, 0, 0, 0}, "1521/out": {1, 0, 0, 0},
		"8080/in": {1, 1, 0, 0}, "8080/out": {0, 0, 0, 0},
		"443/in": {0, 0, 1, 1}, "443/out": {1, 0, 0, 0},
	}
	for i := 0; i < lrs.Len(); i++ {
		a := lrs.At(i).Attributes()
		p, _ := a.Get("port")
		d, _ := a.Get("direction")
		var got [4]float64
		for j, k := range []string{"established", "close_wait", "time_wait", "other"} {
			v, ok := a.Get(k)
			require.True(t, ok)
			got[j] = v.Double()
		}
		require.Equal(t, want[p.Str()+"/"+d.Str()], got, "%s/%s", p.Str(), d.Str())
	}
	require.Equal(t, `{"time":"2026-11-02T10:00:07Z","port":"1521","direction":"in","established":3,"close_wait":0,"time_wait":0,"other":0}`,
		lrs.At(0).Body().Str())
}

// Golden-style check on the full record shape (what reaches OpenObserve).
func TestRecordShape(t *testing.T) {
	ld, err := newTest(t, "testdata/proc").collect()
	require.NoError(t, err)
	lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(2) // 8080 in
	require.Equal(t, map[string]any{"log_type": "netconn", "port": "8080", "direction": "in",
		"established": 1.0, "close_wait": 1.0, "time_wait": 0.0, "other": 0.0}, lr.Attributes().AsRaw())
	require.Equal(t, int64(1793613607000000000), int64(lr.Timestamp()))
}

func TestMissingProc(t *testing.T) {
	_, err := newTest(t, "testdata/nope").collect()
	require.Error(t, err)
}

func TestConfigValidate(t *testing.T) {
	c := createDefaultConfig()
	require.NoError(t, c.Validate())
	c.Ports = []int{0}
	require.Error(t, c.Validate())
}

func TestStartEmits(t *testing.T) {
	sink := new(consumertest.LogsSink)
	cfg := createDefaultConfig()
	cfg.ProcPath = "testdata/proc"
	cfg.CollectionInterval = 20 * time.Millisecond
	r, err := createLogs(context.Background(), receivertest.NewNopSettings(typeStr), cfg, sink)
	require.NoError(t, err)
	require.NoError(t, r.Start(context.Background(), componenttest.NewNopHost()))
	require.Eventually(t, func() bool { return len(sink.AllLogs()) >= 2 }, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, r.Shutdown(context.Background()))
	var _ plog.Logs = sink.AllLogs()[0]
}
