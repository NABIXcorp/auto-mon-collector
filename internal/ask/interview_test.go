package ask

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/internal/detect"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

func appHost() []detect.Finding {
	return []detect.Finding{
		{ID: "nginx", Ports: []int{443}},
		{ID: "oracle", Confidence: "high", Profile: true, Ports: []int{1521},
			Values: map[string]string{"ORACLE_SID": "ORCL", "ORACLE_SERVICE": "orcl"}},
		{ID: "redis", Confidence: "high", Profile: true, Ports: []int{6380}},
		{ID: "tomcat", Confidence: "high", Profile: true, Ports: []int{8080}, Values: map[string]string{"TOMCAT_HTTP_PORT": "8080"}},
	}
}

func TestFirstRunAsksAndSecondRunIsEnterEnter(t *testing.T) {
	s := &Script{Answers: []string{"Shop prod", // project
		"n", "y", "n", "y", // monitor oracle, not redis, tomcat
		"apppdb", "", "", "http://127.0.0.1:8080/app/ https://app.example.com/app/",
		"/opt/tomcat/logs/access_log.*.log", ""}} // Tomcat logs: access log typed, Tomcat log none (default '-')
	a, err := Interview(appHost(), generate.Answers{}, s)
	if err != nil {
		t.Fatalf("%v\n%s", err, s.Out.String())
	}
	if *a.Services["redis"].Enabled || !*a.Services["oracle"].Enabled || !*a.Services["tomcat"].Enabled {
		t.Errorf("enabled: %+v", a.Services)
	}
	if a.Services["oracle"].Service != "apppdb" || a.Services["oracle"].User != "otel_mon" || len(a.Checks.HTTP) != 2 {
		t.Errorf("answers: %+v", a)
	}
	if tc := a.Services["tomcat"]; a.Project != "Shop prod" || tc.AccessLog != "/opt/tomcat/logs/access_log.*.log" ||
		!reflect.DeepEqual(tc.Logs, []string{"-"}) {
		t.Errorf("project / Tomcat logs: %q %+v", a.Project, tc)
	}
	out := s.Out.String()
	for _, want := range []string{"found  oracle", "seen   nginx", "guesses the service from SID ORCL", "Monitor [oracle, redis, tomcat]?"} {
		if !strings.Contains(out, want) {
			t.Errorf("transcript lacks %q:\n%s", want, out)
		}
	}

	// save, load, ask again: Enter everywhere gives the same answers
	b, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\nservices:\n  oracle:\n    enabled: true\n") {
		t.Errorf("answers.yaml must use 2-space indentation:\n%s", b)
	}
	p := filepath.Join(t.TempDir(), "answers.yaml")
	os.WriteFile(p, b, 0o644)
	prev, err := generate.LoadAnswers(p)
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	s2 := &Script{Answers: []string{"", "", "", "", "", "", "", ""}} // project, monitor, service, user, non-CDB, http, 2 x logs
	a2, err := Interview(appHost(), prev, s2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, a2) {
		t.Errorf("second run differs:\nfirst  %+v\nsecond %+v", a, a2)
	}
	if !strings.Contains(s2.Out.String(), "Monitor [oracle, tomcat] (not: redis)?") {
		t.Errorf("the saved 'redis off' must be the default:\n%s", s2.Out.String())
	}
}

func TestDashMeansNoHTTPChecks(t *testing.T) {
	s := &Script{Answers: []string{"", "", "", "", "", "-", "", ""}}
	a, err := Interview(appHost(), generate.Answers{}, s)
	if err != nil || len(a.Checks.HTTP) != 0 || a.Project != "" {
		t.Errorf("%+v %q %v", a.Checks, a.Project, err)
	}
}

// Prod-like host (2026-10-07): Tomcat started by systemd, no catalina.out, renamed access log. The scan's
// globs are the defaults: Enter keeps them and nothing is repeated in answers.yaml.
func TestScannedTomcatLogsAreDefaults(t *testing.T) {
	fs := []detect.Finding{{ID: "tomcat", Confidence: "high", Profile: true, Ports: []int{8080},
		Values: map[string]string{"TOMCAT_HTTP_PORT": "8080", "TOMCAT_ACCESS_LOG": "/opt/tomcat10/logs/access_log.*.log",
			"TOMCAT_JULI_LOGS": "/opt/tomcat10/logs/catalina.*.log /opt/tomcat10/logs/localhost.*.log"}}}
	s := &Script{Answers: []string{"", "", "", "", ""}}
	a, err := Interview(fs, generate.Answers{Project: "Shop online"}, s)
	if err != nil {
		t.Fatalf("%v\n%s", err, s.Out.String())
	}
	if tc := a.Services["tomcat"]; a.Project != "Shop online" || tc.AccessLog != "" || tc.Logs != nil {
		t.Errorf("previous project kept, scanned logs not saved: %q %+v", a.Project, tc)
	}
	for _, want := range []string{"Project [Shop online]", "Tomcat access log [/opt/tomcat10/logs/access_log.*.log]",
		"[/opt/tomcat10/logs/catalina.*.log /opt/tomcat10/logs/localhost.*.log]"} {
		if !strings.Contains(s.Out.String(), want) {
			t.Errorf("transcript lacks %q:\n%s", want, s.Out.String())
		}
	}
}

// A common user (C##...) gets the CDB root question; default = the SID in lower case. A local user does not.
func TestCommonUserAsksCDBService(t *testing.T) {
	s := &Script{Answers: []string{"", "", "apppdb", "C##OTEL_MON", "", "-", "", ""}}
	a, err := Interview(appHost(), generate.Answers{}, s)
	if err != nil {
		t.Fatalf("%v\n%s", err, s.Out.String())
	}
	if o := a.Services["oracle"]; o.User != "C##OTEL_MON" || o.CDBService != "orcl" {
		t.Errorf("oracle answers: %+v", o)
	}
	if !strings.Contains(s.Out.String(), "Oracle CDB root service [orcl]") {
		t.Errorf("transcript:\n%s", s.Out.String())
	}
	s2 := &Script{Answers: []string{"", "", "apppdb", "", "", "-", "", ""}}
	if _, err := Interview(appHost(), generate.Answers{}, s2); err != nil || strings.Contains(s2.Out.String(), "CDB root") {
		t.Errorf("local user: no CDB question (%v):\n%s", err, s2.Out.String())
	}
}

// A local user gets the non-CDB question (v0.8.0); default = the saved answer. A common user does not.
func TestLocalUserAsksNonCDB(t *testing.T) {
	s := &Script{Answers: []string{"", "", "", "", "y", "-", "", ""}}
	a, err := Interview(appHost(), generate.Answers{}, s)
	if err != nil {
		t.Fatalf("%v\n%s", err, s.Out.String())
	}
	if !a.Services["oracle"].NonCDB || !strings.Contains(s.Out.String(), "Non-CDB database?") {
		t.Errorf("oracle answers %+v, transcript:\n%s", a.Services["oracle"], s.Out.String())
	}
	prev := generate.Answers{Services: map[string]generate.Service{"oracle": {NonCDB: true}}}
	s2 := &Script{Answers: []string{"", "", "", "", "", "-", "", ""}}
	if a, err = Interview(appHost(), prev, s2); err != nil || !a.Services["oracle"].NonCDB {
		t.Errorf("Enter must keep the saved non_cdb (%v): %+v", err, a.Services["oracle"])
	}
	s3 := &Script{Answers: []string{"", "", "apppdb", "C##OTEL_MON", "", "-", "", ""}}
	if _, err = Interview(appHost(), generate.Answers{}, s3); err != nil || strings.Contains(s3.Out.String(), "Non-CDB") {
		t.Errorf("common user: no non-CDB question (%v):\n%s", err, s3.Out.String())
	}
}

func TestBadURLIsRejected(t *testing.T) {
	s := &Script{Answers: []string{"", "", "", "", "", "https://user:secretpw@app.example.com/", "", ""}}
	if _, err := Interview(appHost(), generate.Answers{}, s); err == nil || strings.Contains(err.Error(), "secretpw") {
		t.Errorf("URL with credentials must fail without echoing them: %v", err)
	}
}

func TestSecretsNeverInTheTranscript(t *testing.T) {
	s := &Script{Answers: []string{"https://backend.example.com/api/x", "Basic c2VjcmV0", "dbpass99"}}
	m, err := Secrets(s, []string{"OO_ENDPOINT", "OO_AUTH", "ORACLE_MON_PASSWORD"}, "")
	if err != nil || m["OO_AUTH"] != "Basic c2VjcmV0" || m["ORACLE_MON_PASSWORD"] != "dbpass99" {
		t.Fatalf("%v %v", m, err)
	}
	if out := s.Out.String(); strings.Contains(out, "c2VjcmV0") || strings.Contains(out, "dbpass99") {
		t.Errorf("secret in transcript:\n%s", out)
	}
	if _, err := Secrets(&Script{Answers: []string{"x", ""}}, []string{"OO_ENDPOINT", "OO_AUTH"}, ""); err == nil {
		t.Error("an empty secret must fail")
	}
}

func TestNoServices(t *testing.T) {
	s := &Script{Answers: []string{""}} // project
	a, err := Interview(nil, generate.Answers{}, s)
	if err != nil || len(a.Services) != 0 || !strings.Contains(s.Out.String(), "only host metrics") {
		t.Errorf("%+v %v %s", a, err, s.Out.String())
	}
}
