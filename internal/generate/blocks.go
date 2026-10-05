package generate

import (
	"fmt"
	"regexp"
	"strings"
)

// Receiver blocks, taken from configurations that run in production. Only paths, ports and the time zone
// change. A literal $ in collector config is $$ (end of the regexes below).

var plainYAML = regexp.MustCompile(`^[A-Za-z0-9_./*:-]+$`)

// q writes a YAML scalar: plain when safe, single-quoted otherwise.
func q(s string) string {
	if plainYAML.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func httpCheck(checks []HTTPCheck) string {
	var b strings.Builder
	b.WriteString("  # Up checks, run from this host. up = httpcheck_status{http_status_class=\"2xx\"} == 1.\n")
	b.WriteString("  # URLs are labels used by alerts and dashboards: keep them stable.\n")
	b.WriteString("  http_check:\n    collection_interval: 30s\n")
	for _, c := range checks {
		if strings.HasPrefix(c.URL, "https://") {
			b.WriteString("    metrics:\n      httpcheck.tls.cert_remaining:\n        enabled: true\n")
			break
		}
	}
	b.WriteString("    targets:\n")
	for _, c := range checks {
		fmt.Fprintf(&b, "      - endpoint: %s", q(c.URL))
		if c.Comment != "" {
			fmt.Fprintf(&b, "    # %s", strings.ReplaceAll(c.Comment, "\n", " "))
		}
		b.WriteString("\n        method: GET\n        timeout: 10s\n")
	}
	return b.String()
}

func tcpCheck(port int) string {
	return fmt.Sprintf(`  tcp_check:
    collection_interval: 30s
    targets:
      - endpoint: 127.0.0.1:%d    # Oracle listener
        dialer:
          timeout: 5s
`, port)
}

func tomcatAccess(dir string) string {
	return strings.Replace(`  file_log/tomcat_access:
    include: [@INCLUDE@]
    start_at: end
    storage: file_storage
    attributes:
      log_type: tomcat_access
    operators:
      - type: regex_parser
        regex: '^(?P<client_ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+)(?: (?P<duration_ms>\d+))?$$'
        on_error: send_quiet
        timestamp:
          parse_from: attributes.time
          layout_type: gotime
          layout: '02/Jan/2006:15:04:05 -0700'
        severity:
          parse_from: attributes.status
          mapping:
            error: 5xx
            warn: 4xx
            info: [2xx, 3xx]
      - type: regex_parser
        parse_from: attributes.path
        regex: '^/(?P<webapp>[^/?]*)'
        on_error: send_quiet
      - type: remove
        if: 'attributes.time != nil'
        field: attributes.time
`, "@INCLUDE@", q(dir+"/localhost_access_log.*.txt"), 1)
}

func catalina(file, tz string) string {
	return strings.NewReplacer("@INCLUDE@", q(file), "@TZ@", q(tz)).Replace(`  file_log/catalina:
    include: [@INCLUDE@]
    start_at: end
    storage: file_storage
    attributes:
      log_type: tomcat_catalina
    operators:
      - type: recombine
        combine_field: body
        combine_with: "\n"
        source_identifier: attributes["log.file.name"]
        is_first_entry: 'body matches "^[^\\s]" and not (body startsWith "Caused by")'
      - type: regex_parser
        regex: '^(?P<time>\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d{3}) (?P<level>\w+) \[(?P<thread>[^\]]+)\] (?P<logger>\S+) (?P<message>(?s:.*))$$'
        on_error: send_quiet
        timestamp:
          parse_from: attributes.time
          layout_type: gotime
          layout: '02-Jan-2006 15:04:05.000'
          location: @TZ@
        severity:
          parse_from: attributes.level
          mapping:
            error: SEVERE
            warn: WARNING
            info: INFO
            debug: [CONFIG, FINE, FINER, FINEST]
      - type: remove
        if: 'attributes.time != nil'
        field: attributes.time
`)
}

func oracleAlertLog(file string) string {
	return strings.Replace(`  file_log/oracle_alert:
    include: [@INCLUDE@]
    start_at: end
    storage: file_storage
    attributes:
      log_type: oracle_alert
    multiline:
      line_start_pattern: '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
    operators:
      - type: regex_parser
        regex: '^(?P<time>\S+)\n(?P<message>(?s:.*))$$'
        on_error: send_quiet
        timestamp:
          parse_from: attributes.time
          layout_type: gotime
          layout: '2006-01-02T15:04:05.999999-07:00'
      - type: regex_parser
        parse_from: attributes.message
        regex: '(?P<ora_code>ORA-\d{5})'
        if: 'attributes.message != nil'
        on_error: send_quiet
      - type: remove
        if: 'attributes.time != nil'
        field: attributes.time
`, "@INCLUDE@", q(file), 1)
}
