// Package assets holds the files amc installs on every host: the base collector configuration, the systemd
// unit templates and the TCP-connections helper. They are embedded in the binary, so a release is one file.
package assets

import (
	"bytes"
	"embed"
	"text/template"
)

//go:embed config/config.yaml netconn/otel-netconn.sh netconn/otel-kmsg.sh netconn/otel-procs.sh netconn/otel-sshd.sh systemd/*.tmpl
var files embed.FS

// BaseConfig is config/config.yaml (identical on every host).
func BaseConfig() []byte { return mustRead("config/config.yaml") }

// Netconn is the TCP-connections-per-port helper script.
func Netconn() []byte { return mustRead("netconn/otel-netconn.sh") }

// Kmsg is the kernel-messages helper script (v0.5.0): kernel warnings / errors from the journal.
func Kmsg() []byte { return mustRead("netconn/otel-kmsg.sh") }

// Procs is the top-processes helper script (v0.6.0): top CPU / RSS processes, command names only.
func Procs() []byte { return mustRead("netconn/otel-procs.sh") }

// Sshd is the SSH-logins helper script (v0.7.0): sshd login lines, unknown user names masked.
func Sshd() []byte { return mustRead("netconn/otel-sshd.sh") }

// UnitData fills the systemd unit templates.
type UnitData struct {
	Prefix      string   // install root, e.g. /opt/monitoring
	User        string   // collector user, e.g. otelcol-contrib
	SiteConfigs []string // extra --config files (site.d overlay), absolute paths
}

// Unit renders systemd/<name>.service.tmpl.
func Unit(name string, d UnitData) ([]byte, error) {
	t, err := template.New(name).Option("missingkey=error").Parse(string(mustRead("systemd/" + name + ".service.tmpl")))
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, d); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnitNames are the systemd units amc manages, in start order.
var UnitNames = []string{"monitoring-otelcol", "monitoring-netconn", "monitoring-kmsg", "monitoring-procs", "monitoring-sshd"}

func mustRead(p string) []byte {
	b, err := files.ReadFile(p)
	if err != nil {
		panic("embedded asset missing: " + p) // build error, caught by tests
	}
	return b
}
