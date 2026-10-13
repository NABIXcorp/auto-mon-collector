package generate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/internal/detect"
	"gopkg.in/yaml.v3"
)

func oracleFinding() detect.Finding {
	return detect.Finding{ID: "oracle", Confidence: "high", Profile: true, Ports: []int{1521}, Values: map[string]string{
		"ORACLE_MON": "on", "ORACLE_SID": "ORCL", "ORACLE_SERVICE": "orcl", "ORACLE_LISTENER_PORT": "1521",
		"ORACLE_ALERT_LOG": "/u01/app/oracle/diag/rdbms/orcl/ORCL/trace/alert_ORCL.log"}}
}

func tomcatFinding() detect.Finding {
	return detect.Finding{ID: "tomcat", Confidence: "high", Profile: true, Ports: []int{8005, 8080, 9404},
		Values: map[string]string{"TOMCAT_BASE": "/opt/tomcat", "TOMCAT_HTTP_PORT": "8080", "TOMCAT_JMX_PORT": "9404",
			"TOMCAT_GROUP": "tomcat", "TOMCAT_ACCESS_LOG_DIR": "/opt/tomcat/logs", "TOMCAT_CATALINA_OUT": "/opt/tomcat/logs/catalina.out"}}
}

func parse(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatalf("generated YAML does not parse: %v\n%s", err, b)
	}
	return m
}

func pipelines(m map[string]any) map[string]any {
	return m["service"].(map[string]any)["pipelines"].(map[string]any)
}

func TestOracleOnlyUsesDefaultsAndSaysSo(t *testing.T) {
	out, err := Generate(Host{Findings: []detect.Finding{oracleFinding()}}, Answers{})
	if err != nil {
		t.Fatal(err)
	}
	env := string(out.HostEnv)
	for _, want := range []string{"ORACLE_MON=on\n", "ORACLE_SERVICE=orcl\n", "ORACLE_MON_USER=otel_mon\n",
		"ORACLE_ALERT_LOG=/u01/app/oracle/diag/rdbms/orcl/ORCL/trace/alert_ORCL.log\n", `NETCONN_PORTS="1521"`} {
		if !strings.Contains(env, want) {
			t.Errorf("host.env lacks %q:\n%s", want, env)
		}
	}
	if d := strings.Join(out.Defaults, "\n"); !strings.Contains(d, `oracle service "orcl" (guessed`) || !strings.Contains(d, "otel_mon") {
		t.Errorf("guesses must be reported: %v", out.Defaults)
	}
	m := parse(t, out.HostYAML)
	p := pipelines(m)
	if got := p["metrics"].(map[string]any)["receivers"]; len(got.([]any)) != 5 {
		t.Errorf("metrics receivers = %v", got)
	}
	if _, ok := p["logs/oracle"]; !ok {
		t.Error("logs/oracle pipeline missing")
	}
	if _, ok := p["logs"]; ok {
		t.Error("no Tomcat: no logs pipeline")
	}
	if strings.Contains(string(out.HostYAML), "http_check") {
		t.Error("no web app: no http_check")
	}
}

func TestApplicationHost(t *testing.T) {
	on := true
	h := Host{TimeZone: "Asia/Tashkent", Findings: []detect.Finding{oracleFinding(), tomcatFinding(),
		{ID: "redis", Confidence: "high", Profile: true, Ports: []int{6380}},
		{ID: "nginx", Confidence: "high", Ports: []int{80, 443}}}}
	a := Answers{Services: map[string]Service{"oracle": {Service: "apppdb", User: "monitor"}, "redis": {Enabled: &on}}}
	a.Checks.HTTP = []HTTPCheck{{URL: "http://127.0.0.1:8080/app/", Comment: "Tomcat directly"},
		{URL: "https://app.example.com/app/", Comment: "users' path"}}
	out, err := Generate(h, a)
	if err != nil {
		t.Fatal(err)
	}
	env := string(out.HostEnv)
	for _, want := range []string{"ORACLE_SERVICE=apppdb\n", "ORACLE_MON_USER=monitor\n", "TOMCAT_GROUP=tomcat\n",
		"REDIS_PORT=6380\n", `NETCONN_PORTS="80 443 1521 6380 8080"`} {
		if !strings.Contains(env, want) {
			t.Errorf("host.env lacks %q:\n%s", want, env)
		}
	}
	if len(out.Defaults) != 0 {
		t.Errorf("everything answered, no defaults expected: %v", out.Defaults)
	}
	y := string(out.HostYAML)
	for _, want := range []string{"location: Asia/Tashkent", "httpcheck.tls.cert_remaining", "include: [/opt/tomcat/logs/localhost_access_log.*.txt]",
		"endpoint: https://app.example.com/app/", "?$$'"} {
		if !strings.Contains(y, want) {
			t.Errorf("host.yaml lacks %q", want)
		}
	}
	p := pipelines(parse(t, out.HostYAML))
	if got := p["logs"].(map[string]any)["receivers"].([]any); len(got) != 2 {
		t.Errorf("tomcat logs receivers = %v", got)
	}
	if got := p["metrics"].(map[string]any)["receivers"].([]any); got[4] != "http_check" || got[5] != "tcp_check" {
		t.Errorf("metrics receivers = %v", got)
	}
}

func TestRedisSwitches(t *testing.T) {
	off := false
	r6379 := detect.Finding{ID: "redis", Confidence: "high", Profile: true, Ports: []int{6379}}
	out, _ := Generate(Host{Findings: []detect.Finding{r6379}}, Answers{Services: map[string]Service{"redis": {Enabled: &off}}})
	if !strings.Contains(string(out.HostEnv), "REDIS_MON=off\n") {
		t.Errorf("disabled Redis on the default port needs REDIS_MON=off:\n%s", out.HostEnv)
	}
	out, _ = Generate(Host{Findings: []detect.Finding{r6379}}, Answers{})
	if strings.Contains(string(out.HostEnv), "REDIS_") {
		t.Errorf("Redis on 6379 is discovered by default, no switch needed:\n%s", out.HostEnv)
	}
}

func TestDeterministicAndQuoting(t *testing.T) {
	h := Host{Findings: []detect.Finding{oracleFinding(), tomcatFinding()}}
	a, _ := Generate(h, Answers{})
	b, _ := Generate(h, Answers{})
	if string(a.HostYAML) != string(b.HostYAML) || string(a.HostEnv) != string(b.HostEnv) {
		t.Error("output must be deterministic")
	}
	if q("/var/log/my app/x.log") != "'/var/log/my app/x.log'" || q("it's") != "'it''s'" {
		t.Error("special characters must be quoted")
	}
}

// Tomcat log files (v0.3.0): the new scan value gives the same receiver as an old saved scan (TOMCAT_ACCESS_LOG_DIR);
// systemd-started Tomcat (daily JULI files); answers override the scan; nothing found = a DEFAULT line, not silence.
func TestTomcatLogFiles(t *testing.T) {
	tz := "Asia/Tashkent"
	gen := func(v map[string]string, a Answers) Output {
		t.Helper()
		f := detect.Finding{ID: "tomcat", Confidence: "high", Profile: true, Ports: []int{8080}, Values: v}
		out, err := Generate(Host{TimeZone: tz, Findings: []detect.Finding{f}}, a)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	old := gen(map[string]string{"TOMCAT_ACCESS_LOG_DIR": "/opt/tomcat/logs", "TOMCAT_CATALINA_OUT": "/opt/tomcat/logs/catalina.out"}, Answers{})
	cur := gen(map[string]string{"TOMCAT_ACCESS_LOG": "/opt/tomcat/logs/localhost_access_log.*.txt",
		"TOMCAT_CATALINA_OUT": "/opt/tomcat/logs/catalina.out"}, Answers{})
	if string(old.HostYAML) != string(cur.HostYAML) {
		t.Errorf("old and new scan values must give the same config:\n%s\n---\n%s", old.HostYAML, cur.HostYAML)
	}

	prod := gen(map[string]string{"TOMCAT_ACCESS_LOG": "/opt/tomcat10/logs/access_log.*.log",
		"TOMCAT_JULI_LOGS": "/opt/tomcat10/logs/catalina.*.log /opt/tomcat10/logs/localhost.*.log"}, Answers{})
	y := string(prod.HostYAML)
	for _, want := range []string{"include: [/opt/tomcat10/logs/access_log.*.log]",
		"include: [/opt/tomcat10/logs/catalina.*.log, /opt/tomcat10/logs/localhost.*.log]"} {
		if !strings.Contains(y, want) {
			t.Errorf("host.yaml lacks %q:\n%s", want, y)
		}
	}
	if p := pipelines(parse(t, prod.HostYAML)); len(p["logs"].(map[string]any)["receivers"].([]any)) != 2 {
		t.Errorf("both Tomcat log receivers expected: %v", p["logs"])
	}
	for _, d := range prod.Defaults {
		if strings.Contains(d, "Tomcat") {
			t.Errorf("logs were found, no Tomcat default expected: %v", prod.Defaults)
		}
	}

	none := gen(map[string]string{}, Answers{})
	if d := strings.Join(none.Defaults, "\n"); !strings.Contains(d, "services.tomcat.access_log") || !strings.Contains(d, "services.tomcat.logs") {
		t.Errorf("missing logs must be reported as defaults: %v", none.Defaults)
	}
	if strings.Contains(string(none.HostYAML), "file_log") {
		t.Error("no logs found: no file_log receiver")
	}

	ans := Answers{Services: map[string]Service{"tomcat": {AccessLog: "/srv/tc/logs/acc.*.log", Logs: []string{"-"}}}}
	set := gen(map[string]string{"TOMCAT_ACCESS_LOG": "/opt/tomcat/logs/localhost_access_log.*.txt",
		"TOMCAT_CATALINA_OUT": "/opt/tomcat/logs/catalina.out"}, ans)
	if y := string(set.HostYAML); !strings.Contains(y, "include: [/srv/tc/logs/acc.*.log]") || strings.Contains(y, "file_log/catalina") {
		t.Errorf("answers override the scan ('-' = none):\n%s", y)
	}
	if len(set.Defaults) != 0 {
		t.Errorf("answered: no defaults: %v", set.Defaults)
	}

	// time zone of Tomcat's log: answer > JVM zone (scan) > host zone
	juli := map[string]string{"TOMCAT_JULI_LOGS": "/l/catalina.*.log", "TOMCAT_ACCESS_LOG": "/l/a.*.log"}
	if y := string(gen(juli, Answers{}).HostYAML); !strings.Contains(y, "location: Asia/Tashkent") {
		t.Errorf("host zone expected:\n%s", y)
	}
	juli["TOMCAT_TIME_ZONE"] = "Europe/Kyiv"
	if y := string(gen(juli, Answers{}).HostYAML); !strings.Contains(y, "location: Europe/Kyiv") {
		t.Errorf("JVM zone expected:\n%s", y)
	}
	tzAns := Answers{Services: map[string]Service{"tomcat": {TimeZone: "Etc/GMT-2"}}}
	if y := string(gen(juli, tzAns).HostYAML); !strings.Contains(y, "location: Etc/GMT-2") {
		t.Errorf("answered zone expected:\n%s", y)
	}
}

// CDB root checks (v0.4.0): ORACLE_CDB_SERVICE only when answered, and only with a common user.
func TestOracleCDBService(t *testing.T) {
	h := Host{Findings: []detect.Finding{oracleFinding()}}
	out, err := Generate(h, Answers{Services: map[string]Service{"oracle": {Service: "apppdb", User: "C##OTEL_MON", CDBService: "orcl"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ORACLE_MON_USER=C##OTEL_MON\n", "ORACLE_CDB_SERVICE=orcl\n"} {
		if !strings.Contains(string(out.HostEnv), want) {
			t.Errorf("host.env lacks %q:\n%s", want, out.HostEnv)
		}
	}
	for _, a := range []Service{{Service: "apppdb", User: "C##OTEL_MON", CDBService: "-"}, {Service: "apppdb", User: "monitor"}} {
		out, _ = Generate(h, Answers{Services: map[string]Service{"oracle": a}})
		if strings.Contains(string(out.HostEnv), "ORACLE_CDB_SERVICE") {
			t.Errorf("no CDB checks expected for %+v:\n%s", a, out.HostEnv)
		}
	}
	for _, bad := range []Service{{User: "monitor", CDBService: "orcl"}, {User: "C##X", CDBService: "or$cl"}} {
		if err := (Answers{Services: map[string]Service{"oracle": bad}}).Validate(); err == nil {
			t.Errorf("must fail: %+v", bad)
		}
	}
}

// Non-CDB checks (v0.8.0): ORACLE_NONCDB=on only when answered; never together with cdb_service or a common user.
func TestOracleNonCDB(t *testing.T) {
	h := Host{Findings: []detect.Finding{oracleFinding()}}
	out, err := Generate(h, Answers{Services: map[string]Service{"oracle": {Service: "orcl", User: "otel_mon", NonCDB: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out.HostEnv), "ORACLE_NONCDB=on\n") || strings.Contains(string(out.HostEnv), "ORACLE_CDB_SERVICE") {
		t.Errorf("host.env:\n%s", out.HostEnv)
	}
	out, _ = Generate(h, Answers{Services: map[string]Service{"oracle": {Service: "orcl", User: "otel_mon"}}})
	if strings.Contains(string(out.HostEnv), "ORACLE_NONCDB") {
		t.Errorf("no non-CDB checks without the answer:\n%s", out.HostEnv)
	}
	for _, bad := range []Service{{User: "C##OTEL_MON", NonCDB: true}, {User: "otel_mon", NonCDB: true, CDBService: "orcl"}} {
		if err := (Answers{Services: map[string]Service{"oracle": bad}}).Validate(); err == nil {
			t.Errorf("must fail: %+v", bad)
		}
	}
	if err := (Answers{Services: map[string]Service{"tomcat": {NonCDB: true}}}).Validate(); err == nil {
		t.Error("non_cdb on tomcat must fail")
	}
}

// The project becomes OTEL_RESOURCE_ATTRIBUTES for the resource_detection "env" detector, which URL-decodes the
// value (url.QueryUnescape): "Dev servers" -> "Dev+servers" -> "Dev servers". No project = no line at all.
func TestProject(t *testing.T) {
	h := Host{Findings: []detect.Finding{oracleFinding()}}
	out, err := Generate(h, Answers{Project: "Dev servers.1_a-b"})
	if err != nil {
		t.Fatal(err)
	}
	want := "\nOTEL_RESOURCE_ATTRIBUTES=project=Dev+servers.1_a-b\n"
	if !strings.Contains(string(out.HostEnv), want) {
		t.Errorf("host.env lacks %q:\n%s", want, out.HostEnv)
	}
	out, _ = Generate(h, Answers{})
	if strings.Contains(string(out.HostEnv), "OTEL_RESOURCE_ATTRIBUTES") {
		t.Errorf("no project -> no OTEL_RESOURCE_ATTRIBUTES:\n%s", out.HostEnv)
	}
	// round trip: answers.yaml keeps the project
	b, _ := Answers{Project: "Dev servers"}.Marshal()
	p := filepath.Join(t.TempDir(), "a.yaml")
	os.WriteFile(p, b, 0o644)
	if a, err := LoadAnswers(p); err != nil || a.Project != "Dev servers" {
		t.Errorf("round trip: %+v %v\n%s", a, err, b)
	}
}

func TestLoadAnswers(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "a.yaml")
		os.WriteFile(p, []byte(s), 0o644)
		return p
	}
	good := write("services:\n  oracle: {service: apppdb, user: monitor}\n  redis: {enabled: false}\nchecks:\n  http:\n    - url: http://127.0.0.1:8080/app/\n")
	a, err := LoadAnswers(good)
	if err != nil || a.Services["oracle"].Service != "apppdb" || *a.Services["redis"].Enabled || len(a.Checks.HTTP) != 1 {
		t.Fatalf("%+v %v", a, err)
	}
	for _, bad := range []string{
		"services:\n  oracle: {sevice: x}\n",                       // typo: unknown key
		"services:\n  mongodb: {enabled: true}\n",                  // unknown service
		"checks:\n  http:\n    - url: ftp://x/\n",                  // not http
		"checks:\n  http:\n    - url: https://u:p4ss@x.example/\n", // credentials in a URL
		"project: a,b\n",       // "," separates resource attributes
		"project: a=b\n",       // "=" too
		"project: Тест\n",      // not ASCII
		"project: \" lead\"\n", // must start with a letter or digit
		"services:\n  tomcat: {access_log: relative/x.log}\n",      // log path must be absolute
		"services:\n  tomcat: {logs: [\"/a b/c.log\"]}\n",          // no spaces
		"services:\n  oracle: {access_log: /x/access.log}\n",       // Tomcat-only setting
		"services:\n  tomcat: {access_log: \"/x/a.log\\ny: 1\"}\n", // no line breaks (YAML injection)
		"services:\n  tomcat: {time_zone: \"Asia/Tash kent\"}\n",   // not a zone name
		"services:\n  redis: {time_zone: UTC}\n",                   // Tomcat-only setting
	} {
		if _, err := LoadAnswers(write(bad)); err == nil {
			t.Errorf("must fail: %q", bad)
		} else if strings.Contains(err.Error(), "p4ss") {
			t.Errorf("error leaks the password: %v", err)
		}
	}
}

// HTTP metrics from the access log (v0.9.0): connector + cumulative processor + two pipelines, only with an access log;
// the login metric only with login_path.
func TestHTTPMetricsFromAccessLog(t *testing.T) {
	h := Host{Findings: []detect.Finding{tomcatFinding()}}
	out, err := Generate(h, Answers{})
	if err != nil {
		t.Fatal(err)
	}
	y := string(out.HostYAML)
	for _, want := range []string{"signal_to_metrics/http:", "name: tomcat.access.requests", "name: tomcat.access.duration",
		"delta_to_cumulative: {}", "logs/http_metrics:", "receivers: [signal_to_metrics/http]", "exporters: [signal_to_metrics/http]",
		"parse_from: attributes.status"} {
		if !strings.Contains(y, want) {
			t.Errorf("host.yaml lacks %q", want)
		}
	}
	if strings.Contains(y, "tomcat.access.logins") {
		t.Error("no login metric without login_path")
	}
	out, err = Generate(h, Answers{Services: map[string]Service{"tomcat": {LoginPath: "^/app/login"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out.HostYAML), `IsMatch(attributes["path"], "^/app/login")`) {
		t.Errorf("login condition missing:\n%s", out.HostYAML)
	}
	out, _ = Generate(h, Answers{Services: map[string]Service{"tomcat": {AccessLog: "-"}}})
	if strings.Contains(string(out.HostYAML), "signal_to_metrics") {
		t.Error("no access log = no HTTP metrics")
	}
	if _, err := Generate(h, Answers{Services: map[string]Service{"tomcat": {AccessLog: "-", LoginPath: "^/login"}}}); err == nil {
		t.Error("login_path without an access log must fail")
	}
	for _, bad := range []string{`^/a"b`, "^/a b", "(unclosed"} {
		if err := (Answers{Services: map[string]Service{"tomcat": {LoginPath: bad}}}).Validate(); err == nil {
			t.Errorf("login_path %q must fail", bad)
		}
	}
}

// Data Guard + backups (v0.9.0): switches and the service (CDB root when answered).
func TestOracleDataGuardAndBackups(t *testing.T) {
	h := Host{Findings: []detect.Finding{oracleFinding()}}
	out, err := Generate(h, Answers{Services: map[string]Service{"oracle": {Service: "apppdb", User: "C##OTEL_MON", CDBService: "orcl", DataGuard: true, Backups: true}}})
	if err != nil {
		t.Fatal(err)
	}
	e := string(out.HostEnv)
	for _, want := range []string{"ORACLE_DG=on\n", "ORACLE_BACKUP=on\n", "ORACLE_DB_SERVICE=orcl\n"} {
		if !strings.Contains(e, want) {
			t.Errorf("host.env lacks %q:\n%s", want, e)
		}
	}
	out, _ = Generate(h, Answers{Services: map[string]Service{"oracle": {Service: "orcl", User: "otel_mon"}}})
	if strings.Contains(string(out.HostEnv), "ORACLE_DG") || strings.Contains(string(out.HostEnv), "ORACLE_BACKUP") {
		t.Errorf("off by default:\n%s", out.HostEnv)
	}
	if err := (Answers{Services: map[string]Service{"tomcat": {Backups: true}}}).Validate(); err == nil {
		t.Error("backups on tomcat must fail")
	}
}

func TestTCPChecksToOtherHosts(t *testing.T) {
	var a Answers
	a.Checks.TCP = []TCPCheck{{Endpoint: "db.example.com:1521", Comment: "Oracle primary"}, {Endpoint: "[2001:db8::7]:443"}}
	// no Oracle on this host: the receiver holds the neighbour checks only
	out, err := Generate(Host{Findings: []detect.Finding{tomcatFinding()}}, a)
	if err != nil {
		t.Fatal(err)
	}
	y := string(out.HostYAML)
	if strings.Contains(y, "127.0.0.1:1521") || !strings.Contains(y, "endpoint: db.example.com:1521    # Oracle primary") ||
		!strings.Contains(y, "endpoint: '[2001:db8::7]:443'") {
		t.Errorf("tcp_check targets:\n%s", y)
	}
	recv := pipelines(parse(t, out.HostYAML))["metrics"].(map[string]any)["receivers"].([]any)
	if recv[len(recv)-1] != "tcp_check" {
		t.Errorf("tcp_check not in the metrics pipeline: %v", recv)
	}
	// with Oracle: the local listener stays the first (and only loopback) target, in the same receiver
	out, err = Generate(Host{Findings: []detect.Finding{oracleFinding()}}, a)
	if err != nil {
		t.Fatal(err)
	}
	y = string(out.HostYAML)
	if strings.Count(y, "tcp_check:") != 1 || strings.Index(y, "127.0.0.1:1521") > strings.Index(y, "db.example.com:1521") {
		t.Errorf("one receiver, listener first:\n%s", y)
	}
}

func TestTCPCheckValidation(t *testing.T) {
	for ep, want := range map[string]string{
		"db.example.com":       "host:port",
		"http://db:1521":       "host:port",
		"db.example.com:70000": "port 1-65535",
		"127.0.0.1:1521":       "loopback",
		"localhost:6379":       "loopback",
		"[::1]:80":             "loopback",
		"10.0.0.5:1521":        "",
	} {
		var a Answers
		a.Checks.TCP = []TCPCheck{{Endpoint: ep}}
		err := a.Validate()
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%s: %v (want %q)", ep, err, want)
		}
	}
	var a Answers
	a.Checks.TCP = []TCPCheck{{Endpoint: "db:1521"}, {Endpoint: "db:1521"}}
	if err := a.Validate(); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("duplicate: %v", err)
	}
}
