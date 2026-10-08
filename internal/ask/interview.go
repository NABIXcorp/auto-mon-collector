package ask

import (
	"fmt"
	"sort"
	"strings"

	"github.com/NABIXcorp/auto-mon-collector/internal/detect"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

// Interview asks what a scan cannot know. prev (the saved answers of an earlier run) gives the defaults, so
// a repeated run is Enter, Enter. The result names every detected service explicitly (enabled true / false).
func Interview(fs []detect.Finding, prev generate.Answers, p Prompter) (generate.Answers, error) {
	a := generate.Answers{Services: map[string]generate.Service{}}
	// ---- project: groups hosts in reports and dashboards (resource attribute), the previous answer is the default
	def := prev.Project
	if def == "" {
		def = "-"
	}
	p.Say("Project: groups this host with others in reports and dashboards (e.g. a product or environment), '-' = none\n")
	proj, err := p.Ask("Project", def)
	if err != nil {
		return a, err
	}
	if proj = strings.TrimSpace(proj); proj != "-" {
		a.Project = proj
	}
	byID := map[string]detect.Finding{}
	var profiles []string
	for _, f := range fs {
		ports := ""
		if len(f.Ports) > 0 {
			ports = fmt.Sprint(f.Ports)
		}
		if f.Profile {
			byID[f.ID] = f
			profiles = append(profiles, f.ID)
			p.Say("found  %-10s %s %s\n", f.ID, f.Confidence, ports)
		} else {
			p.Say("seen   %-10s %s (no amc profile yet: not monitored)\n", f.ID, ports)
		}
	}
	sort.Strings(profiles)
	if len(profiles) == 0 {
		p.Say("no known service: only host metrics will be collected\n")
		return a, a.Validate()
	}

	// ---- which services
	want := map[string]bool{}
	var on, off []string
	for _, id := range profiles {
		def := byID[id].Confidence == "high" || byID[id].Confidence == "medium"
		if s, ok := prev.Services[id]; ok && s.Enabled != nil {
			def = *s.Enabled
		}
		want[id] = def
		if def {
			on = append(on, id)
		} else {
			off = append(off, id)
		}
	}
	q := fmt.Sprintf("Monitor [%s]", strings.Join(on, ", "))
	if len(off) > 0 {
		q += fmt.Sprintf(" (not: %s)", strings.Join(off, ", "))
	}
	keep, err := p.YesNo(q+"?", true)
	if err != nil {
		return a, err
	}
	if !keep {
		for _, id := range profiles {
			if want[id], err = p.YesNo(fmt.Sprintf("  monitor %s?", id), want[id]); err != nil {
				return a, err
			}
		}
	}
	for _, id := range profiles {
		v := want[id]
		a.Services[id] = generate.Service{Enabled: &v}
	}

	// ---- Oracle: the service name (a PDB has its own) and the monitoring user
	if want["oracle"] {
		o, ps := byID["oracle"], prev.Services["oracle"]
		svcDef := ps.Service
		if svcDef == "" {
			svcDef = o.Values["ORACLE_SERVICE"]
			p.Say("  (the scan guesses the service from SID %s; a PDB has its own service name)\n", o.Values["ORACLE_SID"])
		}
		s := a.Services["oracle"]
		if s.Service, err = p.Ask("Oracle service name", svcDef); err != nil {
			return a, err
		}
		userDef := ps.User
		if userDef == "" {
			userDef = "otel_mon"
		}
		if s.User, err = p.Ask("Oracle monitoring user", userDef); err != nil {
			return a, err
		}
		// CDB root checks (PDB states, role, limits, FRA): only with a common user (C##...)
		if strings.HasPrefix(strings.ToUpper(s.User), "C##") {
			cdbDef := ps.CDBService
			if cdbDef == "" {
				cdbDef = o.Values["ORACLE_SERVICE"] // the SID in lower case = usually the CDB root service
			}
			p.Say("  (CDB root service: PDB open states, database role, limits, FRA; '-' = none)\n")
			if s.CDBService, err = p.Ask("Oracle CDB root service", cdbDef); err != nil {
				return a, err
			}
			s.CDBService = strings.TrimSpace(s.CDBService)
		}
		a.Services["oracle"] = s
	}

	// ---- HTTP up checks (Tomcat): keep the previous list, or the local default
	if want["tomcat"] {
		cur := prev.Checks.HTTP
		if len(cur) == 0 && byID["tomcat"].Values["TOMCAT_HTTP_PORT"] != "" {
			cur = []generate.HTTPCheck{{URL: "http://127.0.0.1:" + byID["tomcat"].Values["TOMCAT_HTTP_PORT"] + "/", Comment: "Tomcat directly"}}
		}
		var urls []string
		for _, c := range cur {
			urls = append(urls, c.URL)
		}
		p.Say("  HTTP up checks: URLs separated by spaces (the application path and the users' URL), '-' = none\n")
		ans, err := p.Ask("HTTP checks", strings.Join(urls, " "))
		if err != nil {
			return a, err
		}
		if strings.TrimSpace(ans) != "-" {
			comment := map[string]string{}
			for _, c := range cur {
				comment[c.URL] = c.Comment
			}
			for _, u := range strings.Fields(ans) {
				a.Checks.HTTP = append(a.Checks.HTTP, generate.HTTPCheck{URL: u, Comment: comment[u]})
			}
		}

		// ---- Tomcat log files: default = previous answer, else what the scan found, else none ('-')
		if err := tomcatLogs(&a, byID["tomcat"], prev.Services["tomcat"], p); err != nil {
			return a, err
		}
	}
	return a, a.Validate()
}

// tomcatLogs asks for the access log and Tomcat's own log. Enter keeps the default; the answer is saved only when
// it differs from the scan, so answers.yaml stays short and a later scan can still find moved files.
func tomcatLogs(a *generate.Answers, t detect.Finding, prev generate.Service, p Prompter) error {
	s := a.Services["tomcat"]
	foundAccess := t.Values["TOMCAT_ACCESS_LOG"]
	if foundAccess == "" && t.Values["TOMCAT_ACCESS_LOG_DIR"] != "" {
		foundAccess = t.Values["TOMCAT_ACCESS_LOG_DIR"] + "/localhost_access_log.*.txt"
	}
	foundLogs := t.Values["TOMCAT_CATALINA_OUT"]
	if foundLogs == "" {
		foundLogs = t.Values["TOMCAT_JULI_LOGS"]
	}
	pick := func(prev, found string) string {
		switch {
		case prev != "":
			return prev
		case found != "":
			return found
		}
		return "-"
	}
	p.Say("  Tomcat logs: file globs (* = any date), '-' = none\n")
	access, err := p.Ask("Tomcat access log", pick(prev.AccessLog, foundAccess))
	if err != nil {
		return err
	}
	if access = strings.TrimSpace(access); access != foundAccess { // incl. "-" when nothing was found: answered
		s.AccessLog = access
	}
	logs, err := p.Ask("Tomcat log (catalina.out format, globs separated by spaces)",
		pick(strings.Join(prev.Logs, " "), foundLogs))
	if err != nil {
		return err
	}
	if f := strings.Fields(logs); strings.Join(f, " ") != foundLogs {
		s.Logs = f
	}
	a.Services["tomcat"] = s
	return nil
}

// Secrets asks for the values of the secrets file (only when it does not exist yet). OO_ENDPOINT is not a
// secret and is shown; the auth header and the database password are read without echo.
func Secrets(p Prompter, keys []string, endpointDefault string) (map[string]string, error) {
	out := map[string]string{}
	p.Say("\nsecrets/collector.env is missing: amc asks for the values (written only by apply, root 600)\n")
	for _, k := range keys {
		var v string
		var err error
		switch k {
		case "OO_ENDPOINT":
			v, err = p.Ask("Backend OTLP endpoint (e.g. https://observe.example.com/api/<org-id>)", endpointDefault)
		case "OO_AUTH":
			v, err = p.Secret("Backend Authorization header value (e.g. Basic <base64>)")
		case "ORACLE_MON_PASSWORD":
			v, err = p.Secret("Oracle monitoring user's password")
		default:
			v, err = p.Secret(k)
		}
		if err != nil {
			return nil, err
		}
		if v == "" {
			return nil, fmt.Errorf("%s: empty value", k)
		}
		out[k] = v
	}
	return out, nil
}
