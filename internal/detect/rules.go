package detect

import (
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Finding is one detected service. Values are the host.env switches a generator would write.
type Finding struct {
	ID         string            `json:"id"`         // oracle, tomcat, redis, caddy, or the process name
	Confidence string            `json:"confidence"` // high = port + process, medium = one of them
	Profile    bool              `json:"profile"`    // amc can monitor it (a profile exists)
	Ports      []int             `json:"ports"`
	PIDs       []int             `json:"pids"`
	Values     map[string]string `json:"values,omitempty"`
	Notes      []string          `json:"notes,omitempty"`
}

var (
	pmonRE   = regexp.MustCompile(`^ora_pmon_(\w+)$`)
	jmxRE    = regexp.MustCompile(`^-javaagent:\S*jmx_prometheus\S*\.jar=(?:[\w.]+:)?(\d+)(?::\S*)?$`)
	otelJava = regexp.MustCompile(`^-javaagent:\S*opentelemetry-javaagent\S*\.jar$`)
)

// Detect turns a snapshot into findings, sorted by id.
func Detect(snap Snapshot, s Source) []Finding {
	var out []Finding
	out = append(out, oracle(snap, s)...)
	out = append(out, tomcat(snap, s)...)
	out = append(out, byComm(snap, "redis", true, "redis-server")...)
	out = append(out, caddy(snap)...)
	for _, other := range []struct{ id, comm string }{{"nginx", "nginx"}, {"postgresql", "postgres"},
		{"postgresql", "postmaster"}, {"mysql", "mysqld"}, {"mysql", "mariadbd"}, {"docker", "dockerd"}} {
		out = append(out, byComm(snap, other.id, false, other.comm)...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return mergeSameID(out)
}

func oracle(snap Snapshot, s Source) []Finding {
	var lsnrPorts, lsnrPIDs []int
	type inst struct {
		sid string
		p   Proc
	}
	var insts []inst
	for _, p := range snap.Procs {
		if p.Comm == "tnslsnr" || (len(p.Args) > 0 && path.Base(p.Args[0]) == "tnslsnr") {
			lsnrPIDs = append(lsnrPIDs, p.PID)
			for _, port := range p.Ports {
				lsnrPorts = appendUnique(lsnrPorts, port)
			}
		}
		if len(p.Args) > 0 {
			if m := pmonRE.FindStringSubmatch(p.Args[0]); m != nil {
				insts = append(insts, inst{m[1], p})
			}
		}
	}
	if len(insts) == 0 && len(lsnrPIDs) == 0 {
		return nil
	}
	sort.Ints(lsnrPorts)
	f := Finding{ID: "oracle", Profile: true, Ports: lsnrPorts, PIDs: lsnrPIDs, Values: map[string]string{}}
	f.Confidence = "medium"
	if len(insts) > 0 && len(lsnrPorts) > 0 {
		f.Confidence = "high"
	}
	switch {
	case len(lsnrPorts) == 0:
		f.Notes = append(f.Notes, "no listener port found: the collector reaches Oracle through the listener")
	case !containsInt(lsnrPorts, 1521):
		f.Notes = append(f.Notes, fmt.Sprintf("listener on %v, not 1521: the base config discovers Oracle on 1521 only", lsnrPorts))
	}
	if len(insts) == 0 {
		f.Notes = append(f.Notes, "listener only, no instance (ora_pmon_*) on this host")
		return []Finding{f}
	}
	if len(insts) > 1 {
		var sids []string
		for _, i := range insts {
			sids = append(sids, i.sid)
		}
		f.Notes = append(f.Notes, fmt.Sprintf("%d instances (%s): v1 monitors one, the first is used", len(insts), strings.Join(sids, ", ")))
	}
	in := insts[0]
	f.PIDs = append(f.PIDs, in.p.PID)
	f.Values["ORACLE_MON"] = "on"
	f.Values["ORACLE_SID"] = in.sid
	f.Values["ORACLE_SERVICE"] = strings.ToLower(in.sid)
	f.Notes = append(f.Notes, "ORACLE_SERVICE is a guess (the SID in lower case); a PDB has its own service name")
	base := in.p.Env["ORACLE_BASE"]
	if base == "" {
		base = "/u01/app/oracle"
		f.Notes = append(f.Notes, "ORACLE_BASE not readable from the instance: assumed "+base)
	}
	if log := alertLog(s, base, in.sid); log != "" {
		f.Values["ORACLE_ALERT_LOG"] = log
	} else {
		f.Notes = append(f.Notes, "alert log not found under "+base+"/diag/rdbms/*/"+in.sid+"/trace/")
	}
	if len(lsnrPorts) > 0 {
		f.Values["ORACLE_LISTENER_PORT"] = strconv.Itoa(lsnrPorts[0])
	}
	return []Finding{f}
}

// alertLog finds <base>/diag/rdbms/<db>/<sid>/trace/alert_<sid>.log; the directory name keeps the SID's case
// or is lower case, so both are tried.
func alertLog(s Source, base, sid string) string {
	for _, v := range []string{sid, strings.ToLower(sid), strings.ToUpper(sid)} {
		m, _ := s.Glob(base + "/diag/rdbms/*/" + v + "/trace/alert_" + v + ".log")
		if len(m) > 0 {
			return m[0]
		}
	}
	return ""
}

func tomcat(snap Snapshot, s Source) []Finding {
	var out []Finding
	for _, p := range snap.Procs {
		base := argValue(p.Args, "-Dcatalina.base=")
		if base == "" {
			continue
		}
		f := Finding{ID: "tomcat", Confidence: "high", Profile: true, Ports: p.Ports, PIDs: []int{p.PID},
			Values: map[string]string{}}
		f.Values["TOMCAT_BASE"] = base
		// Tomcat's own log has local time WITHOUT an offset, in the JVM's zone: -Duser.timezone, else TZ of the
		// process, else the host's zone (seen 2026: a JVM at UTC+2 on a UTC+5 host = entries 3 h off).
		tz := argValue(p.Args, "-Duser.timezone=")
		if tz == "" {
			tz = strings.TrimPrefix(p.Env["TZ"], ":")
		}
		if tz != "" {
			f.Values["TOMCAT_TIME_ZONE"] = tz
			f.Notes = append(f.Notes, "JVM time zone "+tz+" (used for Tomcat's log times)")
		}
		jmx := 0
		for _, a := range p.Args {
			if m := jmxRE.FindStringSubmatch(a); m != nil {
				jmx, _ = strconv.Atoi(m[1])
			}
			if otelJava.MatchString(a) {
				f.Notes = append(f.Notes, "OpenTelemetry Java agent loaded: traces to the collector's OTLP port")
			}
		}
		switch {
		case jmx == 0:
			f.Notes = append(f.Notes, "no JMX exporter javaagent: Tomcat / JVM metrics need it (port 9404)")
		case jmx != 9404:
			f.Notes = append(f.Notes, fmt.Sprintf("JMX exporter on %d, not 9404: the base config discovers 9404 only", jmx))
		}
		if jmx != 0 {
			f.Values["TOMCAT_JMX_PORT"] = strconv.Itoa(jmx)
		}
		for _, port := range p.Ports {
			if port != jmx && port != 8005 && (f.Values["TOMCAT_HTTP_PORT"] == "" || port == 8080) {
				f.Values["TOMCAT_HTTP_PORT"] = strconv.Itoa(port)
			}
		}
		logs := base + "/logs"
		if g, err := s.Group(logs); err == nil && g != "" && g != "root" {
			f.Values["TOMCAT_GROUP"] = g
		}
		// access log: the default name first, then any *access*log* file (AccessLogValve prefix / suffix changed,
		// e.g. access_log.2026-10-07.log). The include glob = the newest name with its date replaced by *.
		access, _ := s.Glob(logs + "/localhost_access_log*")
		if len(access) == 0 {
			access, _ = s.Glob(logs + "/*access*log*")
		}
		if len(access) > 0 {
			f.Values["TOMCAT_ACCESS_LOG"] = datedGlob(access)
		} else {
			f.Notes = append(f.Notes, "no access log in "+logs+" (AccessLogValve off?): answer services.tomcat.access_log")
		}
		// Tomcat's own log: catalina.out (started by catalina.sh), else the daily files of the JULI handlers
		// (started by systemd without catalina.out): catalina.<date>.log and localhost.<date>.log (webapp errors).
		if m, _ := s.Glob(logs + "/catalina.out"); len(m) > 0 {
			f.Values["TOMCAT_CATALINA_OUT"] = m[0]
		} else {
			var juli []string
			for _, name := range []string{"catalina", "localhost"} {
				if m, _ := s.Glob(logs + "/" + name + ".*.log"); len(m) > 0 {
					juli = append(juli, logs+"/"+name+".*.log")
				}
			}
			if len(juli) > 0 {
				f.Values["TOMCAT_JULI_LOGS"] = strings.Join(juli, " ")
			} else {
				f.Notes = append(f.Notes, "no catalina.out or catalina.<date>.log in "+logs+": answer services.tomcat.logs")
			}
		}
		out = append(out, f)
	}
	return out
}

var dateRE = regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)

// datedGlob turns rotated file names into one include glob: the newest name (sorted last) with its date as *.
// Without a date in the name the name itself is used. Compressed rotations (.gz, ...) are skipped: not text.
func datedGlob(files []string) string {
	var plain []string
	for _, f := range files {
		switch path.Ext(f) {
		case ".gz", ".bz2", ".xz", ".zip", ".zst":
		default:
			plain = append(plain, f)
		}
	}
	if len(plain) == 0 {
		plain = files
	}
	sort.Strings(plain)
	return dateRE.ReplaceAllString(plain[len(plain)-1], "*")
}

func caddy(snap Snapshot) []Finding {
	fs := byComm(snap, "caddy", true, "caddy")
	for i := range fs {
		if !containsInt(fs[i].Ports, 2019) {
			fs[i].Confidence = "medium"
			fs[i].Notes = append(fs[i].Notes, "admin endpoint 2019 not listening: no Caddy metrics")
		}
	}
	return fs
}

// byComm finds processes by name; one finding with every matching process.
func byComm(snap Snapshot, id string, profile bool, comm string) []Finding {
	var f *Finding
	for _, p := range snap.Procs {
		if p.Comm != comm {
			continue
		}
		if f == nil {
			f = &Finding{ID: id, Profile: profile, Confidence: "medium"}
		}
		f.PIDs = append(f.PIDs, p.PID)
		for _, port := range p.Ports {
			f.Ports = appendUnique(f.Ports, port)
		}
	}
	if f == nil {
		return nil
	}
	sort.Ints(f.Ports)
	if len(f.Ports) > 0 {
		f.Confidence = "high"
	}
	if !profile {
		f.Notes = append(f.Notes, "no amc profile yet: not monitored")
	}
	if id == "redis" && len(f.Ports) > 0 && f.Ports[0] != 6379 {
		f.Values = map[string]string{"REDIS_PORT": strconv.Itoa(f.Ports[0])}
	}
	return []Finding{*f}
}

func mergeSameID(fs []Finding) []Finding {
	var out []Finding
	for _, f := range fs {
		if n := len(out); n > 0 && out[n-1].ID == f.ID && !f.Profile && !out[n-1].Profile {
			out[n-1].PIDs = append(out[n-1].PIDs, f.PIDs...)
			for _, p := range f.Ports {
				out[n-1].Ports = appendUnique(out[n-1].Ports, p)
			}
			continue
		}
		out = append(out, f)
	}
	return out
}

func argValue(args []string, prefix string) string {
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, prefix); ok {
			return v
		}
	}
	return ""
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// Print writes the findings for people.
func Print(w io.Writer, snap Snapshot, fs []Finding) {
	fmt.Fprintf(w, "host: %s, time zone %s, %d listening port(s): %v\n", orUnknown(snap.OS), orUnknown(snap.TimeZone),
		len(snap.PortsListening()), snap.PortsListening())
	for _, n := range snap.Notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
	if len(fs) == 0 {
		fmt.Fprintln(w, "\nno known service found (only host metrics would be collected)")
		return
	}
	for _, f := range fs {
		mark := "found"
		if !f.Profile {
			mark = "seen "
		}
		fmt.Fprintf(w, "\n%s  %-10s %-6s ports %v  pids %v\n", mark, f.ID, f.Confidence, f.Ports, f.PIDs)
		var keys []string
		for k := range f.Values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "       %s=%s\n", k, f.Values[k])
		}
		for _, n := range f.Notes {
			fmt.Fprintf(w, "       note: %s\n", n)
		}
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown OS"
	}
	return s
}
