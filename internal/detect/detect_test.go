package detect

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// fakeHost builds an in-memory host: processes with their listening sockets.
type fakeHost struct {
	m     Mem
	lines []string
	inode int
}

func newFake() *fakeHost {
	return &fakeHost{m: Mem{Files: map[string]string{"/etc/os-release": "PRETTY_NAME=\"Test Linux 9\"\n"},
		Links: map[string]string{}, Groups: map[string]string{}}, inode: 1000}
}

// proc adds a process; listen = ports it listens on (127.0.0.1 for 8005, 0.0.0.0 otherwise).
func (h *fakeHost) proc(pid int, comm string, args []string, env map[string]string, listen ...int) {
	b := fmt.Sprintf("/proc/%d", pid)
	h.m.Files[b+"/comm"] = comm + "\n"
	h.m.Files[b+"/cmdline"] = strings.Join(args, "\x00") + "\x00"
	var kv []string
	for k, v := range env {
		kv = append(kv, k+"="+v)
	}
	h.m.Files[b+"/environ"] = strings.Join(kv, "\x00")
	h.m.Links[b+"/fd/0"] = "/dev/null"
	for i, port := range listen {
		h.inode++
		ip := "00000000"
		if port == 8005 {
			ip = "0100007F"
		}
		h.lines = append(h.lines, fmt.Sprintf("   %d: %s:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000  54  0 %d 1",
			len(h.lines), ip, port, h.inode))
		h.m.Links[fmt.Sprintf("%s/fd/%d", b, i+3)] = fmt.Sprintf("socket:[%d]", h.inode)
	}
}

func (h *fakeHost) snap() (Snapshot, []Finding) {
	h.m.Files["/proc/net/tcp"] = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		strings.Join(h.lines, "\n") + "\n"
	s := Collect(h.m)
	return s, Detect(s, h.m)
}

func find(fs []Finding, id string) *Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

// Pattern of a database-only host: non-CDB, lower-case SID, listener 1521, no Tomcat.
func TestOracleDatabaseHost(t *testing.T) {
	h := newFake()
	h.proc(100, "tnslsnr", []string{"/u01/app/oracle/product/19c/bin/tnslsnr", "LISTENER", "-inherit"}, nil, 1521)
	h.proc(200, "ora_pmon_prod", []string{"ora_pmon_prod"}, map[string]string{
		"ORACLE_BASE": "/u01/app/oracle", "ORACLE_HOME": "/u01/app/oracle/product/19c", "SECRET_TOKEN": "s3cr3t"})
	h.m.Files["/u01/app/oracle/diag/rdbms/prod/prod/trace/alert_prod.log"] = "x"
	snap, fs := h.snap()
	f := find(fs, "oracle")
	if f == nil || f.Confidence != "high" {
		t.Fatalf("oracle not found / not high: %+v", fs)
	}
	want := map[string]string{"ORACLE_MON": "on", "ORACLE_SID": "prod", "ORACLE_SERVICE": "prod",
		"ORACLE_ALERT_LOG": "/u01/app/oracle/diag/rdbms/prod/prod/trace/alert_prod.log", "ORACLE_LISTENER_PORT": "1521"}
	for k, v := range want {
		if f.Values[k] != v {
			t.Errorf("%s = %q, want %q", k, f.Values[k], v)
		}
	}
	for _, p := range snap.Procs {
		if _, leaked := p.Env["SECRET_TOKEN"]; leaked {
			t.Error("environment keys outside the allowlist must be dropped")
		}
	}
	if find(fs, "tomcat") != nil {
		t.Error("no Tomcat on this host")
	}
}

// Pattern of an application host: Tomcat with JMX exporter + OTel agent, Oracle CDB (upper-case SID).
func TestTomcatAndOracleHost(t *testing.T) {
	h := newFake()
	h.proc(100, "tnslsnr", []string{"tnslsnr", "LISTENER"}, nil, 1521)
	h.proc(200, "ora_pmon_ORCL", []string{"ora_pmon_ORCL"}, map[string]string{"ORACLE_BASE": "/u01/app/oracle"})
	h.m.Files["/u01/app/oracle/diag/rdbms/orcl/ORCL/trace/alert_ORCL.log"] = "x"
	h.proc(300, "java", []string{"/usr/bin/java", "-javaagent:/opt/jmx_exporter/jmx_prometheus_javaagent-1.0.1.jar=127.0.0.1:9404:/opt/jmx_exporter/tomcat.yml",
		"-javaagent:/opt/otel/opentelemetry-javaagent-2.31.1.jar", "-Dcatalina.base=/opt/tomcat", "-Dcatalina.home=/opt/tomcat",
		"org.apache.catalina.startup.Bootstrap", "start"}, nil, 8080, 8005, 9404)
	h.m.Files["/opt/tomcat/logs/localhost_access_log.2026-10-05.txt"] = "x"
	h.m.Files["/opt/tomcat/logs/catalina.out"] = "x"
	h.m.Links["/etc/localtime"] = "../usr/share/zoneinfo/Asia/Tashkent"
	h.m.Groups["/opt/tomcat/logs"] = "tomcat"
	snap, fs := h.snap()
	if snap.TimeZone != "Asia/Tashkent" {
		t.Errorf("TimeZone = %q", snap.TimeZone)
	}
	tc := find(fs, "tomcat")
	if tc == nil {
		t.Fatalf("tomcat not found: %+v", fs)
	}
	for k, v := range map[string]string{"TOMCAT_BASE": "/opt/tomcat", "TOMCAT_JMX_PORT": "9404", "TOMCAT_HTTP_PORT": "8080",
		"TOMCAT_GROUP": "tomcat", "TOMCAT_ACCESS_LOG_DIR": "/opt/tomcat/logs", "TOMCAT_CATALINA_OUT": "/opt/tomcat/logs/catalina.out"} {
		if tc.Values[k] != v {
			t.Errorf("%s = %q, want %q", k, tc.Values[k], v)
		}
	}
	if !strings.Contains(strings.Join(tc.Notes, " "), "OpenTelemetry Java agent") {
		t.Errorf("otel agent not noticed: %v", tc.Notes)
	}
	o := find(fs, "oracle")
	if o == nil || o.Values["ORACLE_SID"] != "ORCL" || o.Values["ORACLE_SERVICE"] != "orcl" ||
		o.Values["ORACLE_ALERT_LOG"] != "/u01/app/oracle/diag/rdbms/orcl/ORCL/trace/alert_ORCL.log" {
		t.Errorf("oracle: %+v", o)
	}
}

func TestOtherServicesAndNotes(t *testing.T) {
	h := newFake()
	h.proc(10, "redis-server", []string{"/usr/bin/redis-server", "127.0.0.1:6380"}, nil, 6380)
	h.proc(11, "caddy", []string{"caddy", "run"}, nil, 443) // no admin endpoint
	h.proc(12, "nginx", []string{"nginx: master process"}, nil, 80)
	h.proc(13, "nginx", []string{"nginx: worker process"}, nil)
	h.proc(14, "tnslsnr", []string{"tnslsnr"}, nil, 1522)
	_, fs := h.snap()
	if r := find(fs, "redis"); r == nil || r.Values["REDIS_PORT"] != "6380" {
		t.Errorf("redis on 6380: %+v", r)
	}
	if c := find(fs, "caddy"); c == nil || c.Confidence != "medium" {
		t.Errorf("caddy without admin endpoint must be medium: %+v", c)
	}
	if n := find(fs, "nginx"); n == nil || n.Profile || len(n.PIDs) != 2 {
		t.Errorf("nginx seen, no profile, both pids: %+v", n)
	}
	o := find(fs, "oracle")
	if o == nil || !strings.Contains(strings.Join(o.Notes, " "), "not 1521") || !strings.Contains(strings.Join(o.Notes, " "), "listener only") {
		t.Errorf("oracle notes: %+v", o)
	}
	var b bytes.Buffer
	Print(&b, Snapshot{OS: "Test"}, fs)
	if !strings.Contains(b.String(), "seen   nginx") || !strings.Contains(b.String(), "REDIS_PORT=6380") {
		t.Errorf("print:\n%s", b.String())
	}
}

func TestParseTCP(t *testing.T) {
	text := "  sl local rem st\n" +
		"   0: 0100007F:24BC 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1 0 111 1\n" +
		"   1: 0100007F:24BC 0100007F:9C40 01 00000000:00000000 00:00000000 00000000 1 0 222 1\n"
	ls := parseTCP(text)
	if len(ls) != 1 || ls[0].IP != "127.0.0.1" || ls[0].Port != 9404 || ls[0].Inode != "111" {
		t.Errorf("parseTCP = %+v", ls)
	}
	if ip := hexIP("00000000000000000000000001000000"); ip != "::1" {
		t.Errorf("hexIP v6 = %s", ip)
	}
}

func TestNoServices(t *testing.T) {
	h := newFake()
	h.proc(1, "systemd", []string{"/sbin/init"}, nil)
	snap, fs := h.snap()
	var b bytes.Buffer
	Print(&b, snap, fs)
	if len(fs) != 0 || !strings.Contains(b.String(), "no known service found") {
		t.Errorf("%v\n%s", fs, b.String())
	}
}
