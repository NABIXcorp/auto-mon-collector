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
