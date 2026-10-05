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
	s := &Script{Answers: []string{"n", "y", "n", "y", // monitor oracle, not redis, tomcat
		"apppdb", "", "http://127.0.0.1:8080/app/ https://app.example.com/app/"}}
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
	p := filepath.Join(t.TempDir(), "answers.yaml")
	os.WriteFile(p, b, 0o644)
	prev, err := generate.LoadAnswers(p)
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	s2 := &Script{Answers: []string{"", "", "", ""}}
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
	s := &Script{Answers: []string{"", "", "", "-"}}
	a, err := Interview(appHost(), generate.Answers{}, s)
	if err != nil || len(a.Checks.HTTP) != 0 {
		t.Errorf("%+v %v", a.Checks, err)
	}
}

func TestBadURLIsRejected(t *testing.T) {
	s := &Script{Answers: []string{"", "", "", "https://user:secretpw@app.example.com/"}}
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
	s := &Script{}
	a, err := Interview(nil, generate.Answers{}, s)
	if err != nil || len(a.Services) != 0 || !strings.Contains(s.Out.String(), "only host metrics") {
		t.Errorf("%+v %v %s", a, err, s.Out.String())
	}
}
