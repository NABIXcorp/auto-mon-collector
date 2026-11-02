package netconnreceiver

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"
)

var typeStr = component.MustNewType("netconn")

func NewFactory() receiver.Factory {
	return receiver.NewFactory(typeStr,
		func() component.Config { return createDefaultConfig() },
		receiver.WithLogs(createLogs, component.StabilityLevelDevelopment))
}

func createLogs(_ context.Context, set receiver.Settings, cfg component.Config, next consumer.Logs) (receiver.Logs, error) {
	return &nc{cfg: cfg.(*Config), next: next, log: set.Logger, now: time.Now}, nil
}

type nc struct {
	cfg    *Config
	next   consumer.Logs
	log    *zap.Logger
	now    func() time.Time
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (r *nc) Start(ctx context.Context, _ component.Host) error {
	ctx, r.cancel = context.WithCancel(context.WithoutCancel(ctx))
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		t := time.NewTicker(r.cfg.CollectionInterval)
		defer t.Stop()
		for {
			if err := r.scrape(ctx); err != nil {
				r.log.Warn("netconn scrape failed", zap.Error(err))
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return nil
}

func (r *nc) Shutdown(context.Context) error {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
	return nil
}

// collect builds the logs: one record per configured port and direction, same body and attributes as the
// file_log/netconn pipeline (body = the JSON line, attributes log_type, port, direction, established, close_wait,
// time_wait, other; counts are doubles because json_parser produced float64).
func (r *nc) collect() (plog.Logs, error) {
	socks, err := readSockets(r.cfg.ProcPath)
	if err != nil {
		return plog.NewLogs(), err
	}
	agg := aggregate(socks, r.cfg.Ports)
	ts := r.now().UTC().Truncate(time.Second)
	ld := plog.NewLogs()
	sl := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()
	for _, p := range r.cfg.Ports {
		for _, dir := range []string{"in", "out"} {
			c := agg[[2]string{strconv.Itoa(p), dir}]
			lr := sl.LogRecords().AppendEmpty()
			lr.SetTimestamp(pcommon.NewTimestampFromTime(ts))
			lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(ts))
			lr.Body().SetStr(fmt.Sprintf(`{"time":"%s","port":"%d","direction":"%s","established":%d,"close_wait":%d,"time_wait":%d,"other":%d}`,
				ts.Format("2006-01-02T15:04:05Z"), p, dir, c.established, c.closeWait, c.timeWait, c.other))
			a := lr.Attributes()
			a.PutStr("log_type", "netconn")
			a.PutStr("port", strconv.Itoa(p))
			a.PutStr("direction", dir)
			a.PutDouble("established", float64(c.established))
			a.PutDouble("close_wait", float64(c.closeWait))
			a.PutDouble("time_wait", float64(c.timeWait))
			a.PutDouble("other", float64(c.other))
		}
	}
	return ld, nil
}

func (r *nc) scrape(ctx context.Context) error {
	ld, err := r.collect()
	if err != nil {
		return err
	}
	return r.next.ConsumeLogs(ctx, ld)
}
