package hostdir

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(p, s string) {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755)
		os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644)
	}
	write("host.yaml", "receivers: {}\n")
	write("host.env", "ORACLE_MON=on\nORACLE_ALERT_LOG=/u01/app/oracle/diag/rdbms/orcl/ORCL/trace/alert_ORCL.log\nTOMCAT_GROUP=tomcat\n")
	write("site.d/10-traces.yaml", "processors: {}\n")
	write("site.d/README.md", "ignored\n")
	d, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d.SecretKeys, []string{"OO_ENDPOINT", "OO_AUTH", "ORACLE_MON_PASSWORD"}) {
		t.Errorf("SecretKeys = %v", d.SecretKeys)
	}
	if len(d.ReadFiles) != 1 || !reflect.DeepEqual(d.Groups, []string{"tomcat"}) {
		t.Errorf("ReadFiles %v Groups %v", d.ReadFiles, d.Groups)
	}
	if len(d.Site) != 1 || d.Site["10-traces.yaml"] == nil {
		t.Errorf("Site = %v", d.Site)
	}
	if !strings.Contains(string(d.Version), "site.d=10-traces.yaml") {
		t.Errorf("Version = %s", d.Version)
	}
}

func TestLoadNeedsHostFiles(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Error("empty dir must fail")
	}
}
