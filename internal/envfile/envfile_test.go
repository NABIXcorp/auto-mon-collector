package envfile

import (
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	in := `# comment
; also a comment
ORACLE_MON=on
ORACLE_SERVICE="orcl"
OO_AUTH='Basic fake=='
export NETCONN_PORTS="1521 8080"
EMPTY=
PASSWORD=123456
`
	got, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"ORACLE_MON": "on", "ORACLE_SERVICE": "orcl", "OO_AUTH": "Basic fake==",
		"NETCONN_PORTS": "1521 8080", "EMPTY": "", "PASSWORD": "123456"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Parse = %v, want %v", got, want)
	}
	if m := Missing(got, []string{"OO_AUTH", "EMPTY", "NOPE"}); !reflect.DeepEqual(m, []string{"EMPTY", "NOPE"}) {
		t.Errorf("Missing = %v", m)
	}
}

func TestParseErrorsNeverEchoValues(t *testing.T) {
	for _, in := range []string{"A=1\r\n", "this is not an assignment secretvalue\n", "1BAD=secretvalue\n"} {
		_, err := Parse([]byte(in))
		if err == nil {
			t.Errorf("Parse(%q): want error", in)
			continue
		}
		if strings.Contains(err.Error(), "secretvalue") {
			t.Errorf("error leaks the line: %v", err)
		}
	}
}

func TestFormatRoundTrip(t *testing.T) {
	env := map[string]string{"OO_AUTH": "Basic abc=", "ORACLE_MON_PASSWORD": "123456"}
	b, err := Format([]string{"OO_AUTH", "ORACLE_MON_PASSWORD"}, env)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "OO_AUTH='Basic abc='\nORACLE_MON_PASSWORD='123456'\n" {
		t.Errorf("Format = %q", b)
	}
	back, _ := Parse(b)
	if !reflect.DeepEqual(back, env) {
		t.Errorf("round trip = %v", back)
	}
	if _, err := Format([]string{"K"}, map[string]string{"K": "it's"}); err == nil {
		t.Error("quote in value must be rejected")
	}
}

func TestSet(t *testing.T) {
	in := "# secrets\nOO_AUTH='Basic x'\nREDIS_PASSWORD=old\nexport REDIS_PASSWORD='older'\nOO_ENDPOINT=https://x"
	got, err := Set([]byte(in), "REDIS_PASSWORD", "n3w pass")
	if err != nil {
		t.Fatal(err)
	}
	want := "# secrets\nOO_AUTH='Basic x'\nREDIS_PASSWORD='n3w pass'\nOO_ENDPOINT=https://x\n"
	if string(got) != want {
		t.Errorf("replace:\n%q\nwant\n%q", got, want)
	}
	got, _ = Set(got, "ORACLE_MON_PASSWORD", "p")
	if env, err := Parse(got); err != nil || env["ORACLE_MON_PASSWORD"] != "p" || env["REDIS_PASSWORD"] != "n3w pass" || env["OO_AUTH"] != "Basic x" {
		t.Errorf("append: %v %q", err, got)
	}
	if _, err := Set(nil, "REDIS_PASSWORD", "it's"); err == nil || strings.Contains(err.Error(), "it's") {
		t.Errorf("quote: %v", err)
	}
}
