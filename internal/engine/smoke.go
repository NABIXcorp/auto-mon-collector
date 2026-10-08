package engine

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// smokeOverlay keeps a second collector away from the one already running on the host: own OTLP ports
// (random), no telemetry listener (8888). Exporters go to a local sink via OO_ENDPOINT.
const smokeOverlay = `# amc smoke run only (never installed)
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:0
      http:
        endpoint: 127.0.0.1:0
service:
  telemetry:
    metrics:
      level: none
      readers: []
`

// Lines that fail the smoke run. validate cannot see them: receiver_creator builds its templates only when
// a port is discovered (e.g. a digits-only password arrives as an int: "failed to load ... template config").
var smokeErrors = []string{"failed to load", "failed to start receiver", "unconvertible", "cannot start pipelines",
	"address already in use", "ORA-01017", "ORA-28000", "ORA-28001"}

// Oracle login failures stop the run at once: every retry is one more failed login, and a profile with
// FAILED_LOGIN_ATTEMPTS locks the monitoring account.
var smokeStopNow = []string{"ORA-01017", "ORA-28000", "ORA-28001"}

func (e *eng) smoke(ctx context.Context, tmp string, configs, env []string) bool {
	e.r.step("8b. smoke run (%s, local sink: nothing is sent to the backend)", e.o.SmokeTime)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.r.fail("smoke sink: %v", err)
		return false
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // accept every export, keep nothing
	})}
	go srv.Serve(ln)
	defer srv.Close()

	overlay := filepath.Join(tmp, "stage", "zz-smoke.yaml")
	if err := os.WriteFile(overlay, []byte(smokeOverlay), 0o600); err != nil {
		e.r.fail("smoke overlay: %v", err)
		return false
	}
	// Own data dir always: the running collector holds locks on the real queue / bookmarks.
	data := filepath.Join(tmp, "smoke-data")
	for _, sub := range []string{"file_storage", "netconn", "kmsg", "procs"} {
		if err := os.MkdirAll(filepath.Join(data, sub), 0o700); err != nil {
			e.r.fail("smoke data dir: %v", err)
			return false
		}
	}
	var senv []string
	for _, kv := range env {
		if !strings.HasPrefix(kv, "OO_ENDPOINT=") && !strings.HasPrefix(kv, "MONITORING_DATA=") {
			senv = append(senv, kv)
		}
	}
	senv = append(senv, "OO_ENDPOINT=http://"+ln.Addr().String(), "MONITORING_DATA="+data)
	args := append(append([]string{}, configs...), "--config="+overlay)

	stop := func(line string) bool {
		for _, p := range smokeStopNow {
			if strings.Contains(line, p) {
				return true
			}
		}
		return false
	}
	out, err := e.o.Runner.Timed(ctx, senv, e.o.SmokeTime, stop, e.bin, args...)
	text := e.mask(string(out))
	if err != nil {
		e.r.fail("the collector stopped during the smoke run: %v", err)
		lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
		e.r.indent(strings.Join(lines[max(0, len(lines)-20):], "\n"), 20)
		return false
	}
	started := strings.Count(text, "starting receiver")
	var bad []string
	oracleLogin := false
	for _, l := range strings.Split(text, "\n") {
		for _, p := range smokeErrors {
			if strings.Contains(l, p) {
				bad = append(bad, l)
				if stop(l) {
					oracleLogin = true
				}
				break
			}
		}
	}
	if oracleLogin {
		e.r.fail("Oracle rejected the monitoring login (wrong user / password, or the account is locked / expired). " +
			"Stopped at once so the account is not locked by retries.")
	}
	if len(bad) > 0 {
		e.r.fail("%d error line(s) in the smoke run:", len(bad))
		e.r.indent(strings.Join(bad[:min(len(bad), 10)], "\n"), 10)
		return false
	}
	e.r.ok("ran %s: %s, no load / start errors", e.o.SmokeTime, plural(started, "discovered receiver"))
	return true
}

func plural(n int, what string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", what)
	}
	return fmt.Sprintf("%d %ss", n, what)
}
