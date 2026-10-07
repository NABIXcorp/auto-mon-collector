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
