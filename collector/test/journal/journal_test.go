//go:build linux

// Package journal tests collector/config/journal.yaml (phase D2) with the real journald receiver and transform
// processor: a fake journalctl prints journal JSON fixtures, the output must equal the golden files. This is the CI
// proof that the collector, which may read the whole journal, only lets the fixed fields leave it and masks the
// names of unknown SSH users. Update the golden files after a deliberate change: go test -run . -update
package journal

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/journaldreceiver"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/confmaptest"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor/processortest"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// typed into the SSH user field in the fixtures; must never leave the collector
var secrets = []string{"Secr3tPass", "my pass word", "quote", "Byt3sPass"}

// Allowed attributes per source: everything else from the journal must be gone.
var allowed = map[string][]string{
	"kmsg": {"PRIORITY", "kind", "log_type"},
	"sshd": {"event", "log_type", "method", "src_ip", "user"},
}

// fake journalctl: records its arguments, prints the fixture of its source, then waits like --follow
const fakeJournalctl = `#!/bin/sh
case " $* " in *" --dmesg "*) src=kmsg ;; *) src=sshd ;; esac
printf '%s\n' "$*" > "$JOURNAL_TEST_OUT/args-$src"
cat "$JOURNAL_TEST_FIXTURES/$src.jsonl"
exec sleep 600
`

// loadConfig reads the fragment like the collector does: "$$" in the file is a literal "$".
func loadConfig(t *testing.T) *confmap.Conf {
	b, err := os.ReadFile("../../config/journal.yaml")
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "journal.yaml")
	require.NoError(t, os.WriteFile(p, []byte(strings.ReplaceAll(string(b), "$$", "$")), 0o600))
	c, err := confmaptest.LoadConf(p)
	require.NoError(t, err)
	return c
}

type record struct {
	Time     string            `json:"time"`
	Severity string            `json:"severity,omitempty"`
	Body     string            `json:"body"`
	Attrs    map[string]string `json:"attributes"`
}

func TestJournal(t *testing.T) {
	fixtures, err := filepath.Abs("testdata")
	require.NoError(t, err)
	out := t.TempDir()
	fake := filepath.Join(out, "journalctl")
	require.NoError(t, os.WriteFile(fake, []byte(fakeJournalctl), 0o755))
	t.Setenv("JOURNAL_TEST_FIXTURES", fixtures)
	t.Setenv("JOURNAL_TEST_OUT", out)
	conf := loadConfig(t)

	for src, want := range map[string]int{"kmsg": 4, "sshd": 14} {
		t.Run(src, func(t *testing.T) {
			sink := new(consumertest.LogsSink)
			var next consumer.Logs = sink
			ctx := context.Background()
			host := componenttest.NewNopHost()

			if src == "sshd" { // transform/sshd is the first (here: only) processor of the sshd pipeline
				pf := transformprocessor.NewFactory()
				pcfg := pf.CreateDefaultConfig()
				sub, err := conf.Sub("processors::transform/sshd")
				require.NoError(t, err)
				require.NoError(t, sub.Unmarshal(pcfg))
				p, err := pf.CreateLogs(ctx, processortest.NewNopSettings(pf.Type()), pcfg, sink)
				require.NoError(t, err)
				require.NoError(t, p.Start(ctx, host))
				defer func() { require.NoError(t, p.Shutdown(ctx)) }()
				next = p
			}

			rf := journaldreceiver.NewFactory()
			rcfg := rf.CreateDefaultConfig().(*journaldreceiver.JournaldConfig)
			sub, err := conf.Sub("receivers::journald/" + src)
			require.NoError(t, err)
			require.NoError(t, sub.Unmarshal(rcfg))
			require.NotNil(t, rcfg.BaseConfig.StorageID, "the cursor must be kept in file_storage")
			rcfg.BaseConfig.StorageID = nil // no storage extension in the test host
			rcfg.InputConfig.JournalctlPath = fake
			r, err := rf.CreateLogs(ctx, receivertest.NewNopSettings(rf.Type()), rcfg, next)
			require.NoError(t, err)
			require.NoError(t, r.Start(ctx, host))
			require.Eventually(t, func() bool { return sink.LogRecordCount() >= want }, 15*time.Second, 50*time.Millisecond)
			time.Sleep(300 * time.Millisecond) // nothing more may follow
			require.NoError(t, r.Shutdown(ctx))
			require.Equal(t, want, sink.LogRecordCount())

			args, err := os.ReadFile(filepath.Join(out, "args-"+src))
			require.NoError(t, err)
			got := []string{"# journalctl " + strings.TrimSpace(string(args))}
			for _, rec := range records(sink.AllLogs()) {
				keys := make([]string, 0, len(rec.Attrs))
				for k := range rec.Attrs {
					keys = append(keys, k)
				}
				require.Subset(t, allowed[src], keys, "attribute not on the allowlist: %q", rec.Body)
				b, err := json.Marshal(rec)
				require.NoError(t, err)
				for _, s := range secrets {
					require.NotContains(t, string(b), s, "unmasked user name left the collector")
				}
				got = append(got, string(b))
			}
			golden := filepath.Join("testdata", src+".golden")
			if *update {
				require.NoError(t, os.WriteFile(golden, []byte(strings.Join(got, "\n")+"\n"), 0o644))
			}
			exp, err := os.ReadFile(golden)
			require.NoError(t, err)
			require.Equal(t, string(exp), strings.Join(got, "\n")+"\n")
		})
	}
}

func records(all []plog.Logs) []record {
	var recs []record
	for _, l := range all {
		for i := 0; i < l.ResourceLogs().Len(); i++ {
			sl := l.ResourceLogs().At(i).ScopeLogs()
			for j := 0; j < sl.Len(); j++ {
				lr := sl.At(j).LogRecords()
				for k := 0; k < lr.Len(); k++ {
					r := lr.At(k)
					rec := record{Time: r.Timestamp().AsTime().UTC().Format(time.RFC3339), Severity: r.SeverityText(),
						Body: r.Body().AsString(), Attrs: map[string]string{}}
					r.Attributes().Range(func(k string, v pcommon.Value) bool { rec.Attrs[k] = v.AsString(); return true })
					recs = append(recs, rec)
				}
			}
		}
	}
	sort.SliceStable(recs, func(a, b int) bool { return recs[a].Time < recs[b].Time })
	return recs
}
