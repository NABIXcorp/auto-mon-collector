package procsreceiver

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os/user"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"
)

var typeStr = component.MustNewType("procs")

func NewFactory() receiver.Factory {
	return receiver.NewFactory(typeStr,
		func() component.Config { return createDefaultConfig() },
		receiver.WithLogs(createLogs, component.StabilityLevelDevelopment))
}

func createLogs(_ context.Context, set receiver.Settings, cfg component.Config, next consumer.Logs) (receiver.Logs, error) {
	return &pr{cfg: cfg.(*Config), next: next, log: set.Logger, now: time.Now, lookup: lookupUser,
		names: map[string]string{}}, nil
}

// lookupUser: name for a uid like `ps -o user` (pure Go reads /etc/passwd); the uid itself when unknown.
func lookupUser(uid string) string {
	if u, err := user.LookupId(uid); err == nil {
		return u.Username
	}
	return uid
}

type pr struct {
	cfg    *Config
	next   consumer.Logs
	log    *zap.Logger
	now    func() time.Time
	lookup func(uid string) string
	names  map[string]string // uid -> name cache (only used from the receiver goroutine)
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (r *pr) Start(ctx context.Context, _ component.Host) error {
	ctx, r.cancel = context.WithCancel(context.WithoutCancel(ctx))
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		t := time.NewTicker(r.cfg.CollectionInterval)
		defer t.Stop()
		for {
			if err := r.scrape(ctx); err != nil && ctx.Err() == nil {
				r.log.Warn("procs scrape failed", zap.Error(err))
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

func (r *pr) Shutdown(context.Context) error {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
	return nil
}

func (r *pr) scrape(ctx context.Context) error {
	a, err := snapshot(r.cfg.ProcPath)
	if err != nil {
		return err
	}
	t0 := r.now()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(r.cfg.Window):
	}
	b, err := snapshot(r.cfg.ProcPath)
	if err != nil {
		return err
	}
	up, err := uptimeSeconds(r.cfg.ProcPath)
	if err != nil {
		return err
	}
	t1 := r.now()
	return r.next.ConsumeLogs(ctx, r.build(pick(a, b, t1.Sub(t0).Seconds(), up, r.cfg.Top), t1))
}

// build: one record per process, same body and attributes as the file_log/procs pipeline (body = the JSON line of
// otel-procs.sh; json_parser turned every field into an attribute, numbers as doubles; time became the timestamp).
func (r *pr) build(rows []row, now time.Time) plog.Logs {
	ts := now.UTC().Truncate(time.Second)
	ld := plog.NewLogs()
	sl := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()
	for _, p := range rows {
		name, ok := r.names[p.uid]
		if !ok {
			name = r.lookup(p.uid)
			r.names[p.uid] = name
		}
		cpu := math.Round(p.cpu*10) / 10
		lr := sl.LogRecords().AppendEmpty()
		lr.SetTimestamp(pcommon.NewTimestampFromTime(ts))
		lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(ts))
		lr.Body().SetStr(fmt.Sprintf(`{"time":"%s","pid":%d,"user":%s,"comm":%s,"rss_kb":%d,"cpu_pct":%.1f,"etime_s":%d,"top":"%s"}`,
			ts.Format("2006-01-02T15:04:05Z"), p.pid, jsonStr(name), jsonStr(p.comm), p.rssKB, cpu, p.etime, p.top))
		a := lr.Attributes()
		a.PutStr("log_type", "processes")
		a.PutDouble("pid", float64(p.pid))
		a.PutStr("user", name)
		a.PutStr("comm", p.comm)
		a.PutDouble("rss_kb", float64(p.rssKB))
		a.PutDouble("cpu_pct", cpu)
		a.PutDouble("etime_s", float64(p.etime))
		a.PutStr("top", p.top)
	}
	return ld
}

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
