package generate

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/NABIXcorp/auto-mon-collector/internal/detect"
)

// Host is the detection input: findings + facts the templates need.
type Host struct {
	Findings []detect.Finding
	TimeZone string
}

// Output is the generated host part plus what the operator should confirm.
type Output struct {
	HostYAML []byte
	HostEnv  []byte
	Enabled  []string // services that will be monitored
	Defaults []string // values taken from a default or a guess (the questions in interactive mode)
}

const defaultOracleUser = "otel_mon"

// Generate builds host.yaml and host.env.
func Generate(h Host, a Answers) (Output, error) {
	var out Output
	f := map[string]*detect.Finding{}
	for i := range h.Findings {
		if h.Findings[i].Profile {
			f[h.Findings[i].ID] = &h.Findings[i]
		}
	}
	on := func(id string) bool {
		if f[id] == nil {
			return false
		}
		if s, ok := a.Services[id]; ok && s.Enabled != nil {
			return *s.Enabled
		}
		return f[id].Confidence == "high" || f[id].Confidence == "medium"
	}
	for _, id := range []string{"caddy", "oracle", "redis", "tomcat"} {
		if on(id) {
			out.Enabled = append(out.Enabled, id)
		}
	}

	var env []string
	var netconn []int
	recv := map[string]string{}
	var metrics, tomcatLogs []string
	oracleLog := ""

	// ---- Oracle
	if on("oracle") {
		o, ans := f["oracle"], a.Services["oracle"]
		svc := ans.Service
		if svc == "" {
			svc = o.Values["ORACLE_SERVICE"]
			out.Defaults = append(out.Defaults, fmt.Sprintf("oracle service %q (guessed from SID %s; a PDB has its own name)", svc, o.Values["ORACLE_SID"]))
		}
		user := ans.User
		if user == "" {
			user = defaultOracleUser
			out.Defaults = append(out.Defaults, fmt.Sprintf("oracle monitoring user %q (default)", user))
		}
		if svc == "" {
			return out, fmt.Errorf("oracle: no service name (answer services.oracle.service)")
		}
		env = append(env, "ORACLE_MON=on", "ORACLE_SERVICE="+svc, "ORACLE_MON_USER="+user)
		if p := o.Values["ORACLE_ALERT_LOG"]; p != "" {
			env = append(env, "ORACLE_ALERT_LOG="+p)
			recv["file_log/oracle_alert"] = oracleAlertLog(p)
			oracleLog = "file_log/oracle_alert"
		}
		if p, err := strconv.Atoi(o.Values["ORACLE_LISTENER_PORT"]); err == nil {
			recv["tcp_check"] = tcpCheck(p)
			metrics = append(metrics, "tcp_check")
			netconn = append(netconn, p)
		}
	}

	// ---- Tomcat
	if on("tomcat") {
		t := f["tomcat"]
		if g := t.Values["TOMCAT_GROUP"]; g != "" {
			env = append(env, "TOMCAT_GROUP="+g)
		}
		ans := a.Services["tomcat"]
		access := ans.AccessLog
		switch {
		case access != "":
		case t.Values["TOMCAT_ACCESS_LOG"] != "":
			access = t.Values["TOMCAT_ACCESS_LOG"]
		case t.Values["TOMCAT_ACCESS_LOG_DIR"] != "": // scans saved by amc <= v0.2.0
			access = t.Values["TOMCAT_ACCESS_LOG_DIR"] + "/localhost_access_log.*.txt"
		default:
			out.Defaults = append(out.Defaults, "no Tomcat access log found: no HTTP status / latency from logs "+
				"(answer services.tomcat.access_log: a glob, or '-' for none)")
		}
		if access != "" && access != "-" {
			recv["file_log/tomcat_access"] = tomcatAccess(access)
			tomcatLogs = append(tomcatLogs, "file_log/tomcat_access")
		}
		files := ans.Logs
		switch {
		case len(files) > 0:
		case t.Values["TOMCAT_CATALINA_OUT"] != "":
			files = []string{t.Values["TOMCAT_CATALINA_OUT"]}
		case t.Values["TOMCAT_JULI_LOGS"] != "":
			files = strings.Fields(t.Values["TOMCAT_JULI_LOGS"])
		default:
			out.Defaults = append(out.Defaults, "no Tomcat log (catalina.out / catalina.<date>.log) found: no exceptions "+
				"from logs (answer services.tomcat.logs: a list of globs, or [\"-\"] for none)")
		}
		if len(files) > 0 && files[0] != "-" {
			tz := ans.TimeZone // answer > the JVM's zone (scan) > the host's zone
			if tz == "" {
				tz = t.Values["TOMCAT_TIME_ZONE"]
			}
			if tz == "" {
				tz = h.TimeZone
			}
			if tz == "" {
				tz = "Local"
				out.Defaults = append(out.Defaults, "Tomcat log time zone: the collector's local zone (host zone unknown)")
			}
			recv["file_log/catalina"] = catalina(files, tz)
			tomcatLogs = append(tomcatLogs, "file_log/catalina")
		}
		if p, err := strconv.Atoi(t.Values["TOMCAT_HTTP_PORT"]); err == nil {
			netconn = append(netconn, p)
		}
	}

	// ---- Redis: the base config discovers it on REDIS_PORT (default 6379)
	if r := f["redis"]; r != nil {
		port := 6379
		if len(r.Ports) > 0 {
			port = r.Ports[0]
		}
		switch {
		case on("redis") && port != 6379:
			env = append(env, "REDIS_PORT="+strconv.Itoa(port))
		case !on("redis") && port == 6379:
			env = append(env, "REDIS_MON=off")
		}
		if on("redis") {
			netconn = append(netconn, port)
		}
	}

	// ---- seen services without a profile still count for connection statistics (e.g. nginx 443)
	for _, fd := range h.Findings {
		if fd.ID == "nginx" {
			for _, p := range fd.Ports {
				if p == 443 || p == 80 {
					netconn = append(netconn, p)
				}
			}
		}
	}

	// ---- HTTP up checks
	checks := a.Checks.HTTP
	if len(checks) == 0 && on("tomcat") && f["tomcat"].Values["TOMCAT_HTTP_PORT"] != "" {
		u := "http://127.0.0.1:" + f["tomcat"].Values["TOMCAT_HTTP_PORT"] + "/"
		checks = []HTTPCheck{{URL: u, Comment: "Tomcat directly"}}
		out.Defaults = append(out.Defaults, "HTTP check "+u+" (default; add the application path and the users' URL)")
	}
	if len(checks) > 0 {
		recv["http_check"] = httpCheck(checks)
		metrics = append([]string{"http_check"}, metrics...)
	}

	if len(netconn) > 0 {
		env = append(env, `NETCONN_PORTS="`+joinInts(uniqSorted(netconn))+`"`)
	}
	// ---- project: read by the resource_detection "env" detector (values are URL-decoded there: "+" = space)
	if a.Project != "" {
		env = append(env, "OTEL_RESOURCE_ATTRIBUTES=project="+url.QueryEscape(a.Project))
	}

	// ---- write
	var y strings.Builder
	y.WriteString("# config/host.yaml: generated by amc from `amc detect` + answers. Do not edit: change the answers\n")
	y.WriteString("# and run `amc plan`. Merged on top of config.yaml (maps merge, lists are replaced: full lists below).\n")
	if len(recv) > 0 {
		y.WriteString("receivers:\n")
		for _, name := range []string{"http_check", "tcp_check", "file_log/tomcat_access", "file_log/catalina", "file_log/oracle_alert"} {
			if r, ok := recv[name]; ok {
				y.WriteString(r)
				y.WriteString("\n")
			}
		}
	}
	y.WriteString("service:\n  pipelines:\n    metrics:\n")
	fmt.Fprintf(&y, "      receivers: [%s]\n", strings.Join(append([]string{"host_metrics", "prometheus/otelcol", "otlp",
		"receiver_creator/metrics"}, metrics...), ", "))
	if len(tomcatLogs) > 0 {
		fmt.Fprintf(&y, "    logs:\n      receivers: [%s]\n      processors: [resource_detection, batch]\n"+
			"      exporters: [otlp_http/openobserve_logs]\n", strings.Join(tomcatLogs, ", "))
	}
	if oracleLog != "" {
		fmt.Fprintf(&y, "    logs/oracle:\n      receivers: [%s]\n      processors: [resource_detection, batch]\n"+
			"      exporters: [otlp_http/openobserve_oracle_logs]\n", oracleLog)
	}
	out.HostYAML = []byte(y.String())

	var e strings.Builder
	e.WriteString("# config/host.env: generated by amc (switches for config.yaml; read by systemd). NO secrets here:\n")
	e.WriteString("# they are in secrets/collector.env. Do not edit: change the answers and run `amc plan`.\n")
	for _, kv := range env {
		e.WriteString(kv + "\n")
	}
	out.HostEnv = []byte(e.String())
	return out, nil
}

func uniqSorted(xs []int) []int {
	m := map[int]bool{}
	var out []int
	for _, x := range xs {
		if !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	sort.Ints(out)
	return out
}

func joinInts(xs []int) string {
	s := make([]string, len(xs))
	for i, x := range xs {
		s[i] = strconv.Itoa(x)
	}
	return strings.Join(s, " ")
}
