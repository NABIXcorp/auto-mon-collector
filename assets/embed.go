// Package assets holds the files amc installs on every host: the base collector configuration, the journal fragment
// and the systemd unit templates. They are embedded in the binary, so a release is one file.
package assets

import (
	"bytes"
	"embed"
	"text/template"
)

//go:embed config/config.yaml config/journal.yaml systemd/*.tmpl polkit/50-amc-agent.rules
var files embed.FS

// BaseConfig is config/config.yaml (identical on every host).
func BaseConfig() []byte { return mustRead("config/config.yaml") }

// JournalConfig is config/journal.yaml (v0.19.0): kernel warnings + sshd logins from the journal, a byte-for-byte
// copy of collector/config/journal.yaml (tested there with golden files; TestJournalConfigIsTheTestedOne).
func JournalConfig() []byte { return mustRead("config/journal.yaml") }

// UnitData fills the systemd unit templates.
type UnitData struct {
	Prefix      string   // install root, e.g. /opt/monitoring
	User        string   // collector user, e.g. otelcol-contrib
	SiteConfigs []string // extra --config files (site.d overlay), absolute paths
	Ping        bool     // monitoring-cloudprober: ping probes need CAP_NET_RAW
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
var UnitNames = []string{"monitoring-collector"}

// LegacyUnits (before v0.19.0): otelcol-contrib + the four helper units (bash scripts in <prefix>/netconn). An apply
// stops, disables and unlinks them; a rollback brings them back.
var LegacyUnits = []string{"monitoring-otelcol", "monitoring-netconn", "monitoring-kmsg", "monitoring-procs", "monitoring-sshd"}

// LegacyScripts are the helper scripts of LegacyUnits (removed by an apply, restored by a rollback).
var LegacyScripts = []string{"netconn/otel-netconn.sh", "netconn/otel-kmsg.sh", "netconn/otel-procs.sh", "netconn/otel-sshd.sh"}

// ProbeUnit (v0.12.0) is the Cloudprober unit: managed only when the answers have probes (or an agent).
const ProbeUnit = "monitoring-cloudprober"

// AgentUnit (v0.13.0) is the amc agent: managed only when the answers have an agent section.
const AgentUnit = "monitoring-agent"

// UpdateUnit (v0.16.0) is the root oneshot `amc self-update`, started by the agent (polkit: start only). Managed
// with the agent; linked but never enabled, restarted or checked by apply.
const UpdateUnit = "monitoring-update"

// AgentPolkit is the polkit rule that lets the agent restart Cloudprober and start the self-update unit (only those
// units, only those verbs).
func AgentPolkit() []byte { return mustRead("polkit/50-amc-agent.rules") }

func mustRead(p string) []byte {
	b, err := files.ReadFile(p)
	if err != nil {
		panic("embedded asset missing: " + p) // build error, caught by tests
	}
	return b
}
