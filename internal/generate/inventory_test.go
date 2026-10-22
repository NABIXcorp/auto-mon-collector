package generate

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/internal/detect"
)

func inventoryHost() Host {
	return Host{
		OS: "Rocky Linux 9.4",
		Findings: []detect.Finding{
			{ID: "docker", Confidence: "medium", PIDs: []int{50}},
			{ID: "oracle", Confidence: "high", Profile: true, Ports: []int{1521}, PIDs: []int{100, 200},
				Instances: []string{"ORCL", "TEST2"}, Values: map[string]string{"ORACLE_SID": "ORCL",
					"ORACLE_ALERT_LOG": "/u01/app/oracle/diag/rdbms/orcl/ORCL/trace/alert_ORCL.log"}},
			{ID: "tomcat", Confidence: "high", Profile: true, Ports: []int{9404, 8080, 8005}, PIDs: []int{300},
				Apps: []string{"/", "/shop"}, Values: map[string]string{"TOMCAT_BASE": "/opt/tomcat", "TOMCAT_HTTP_PORT": "8080"}},
		},
		Listen: []detect.Listen{{IP: "0.0.0.0", Port: 22}, {IP: "::", Port: 22}, {IP: "::ffff:10.0.0.5", Port: 8080, Inode: "7"},
			{IP: "10.0.0.5", Port: 8080, Inode: "8"}, {IP: "0.0.0.0", Port: 1521}, {IP: "127.0.0.1", Port: 9404}},
	}
}

func TestInventory(t *testing.T) {
	b := Inventory(inventoryHost(), []string{"oracle"})
	var doc InventoryDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != InventorySchema || doc.OS != "Rocky Linux 9.4" || len(doc.Services) != 3 {
		t.Fatalf("doc: %s", b)
	}
	tc := doc.Services[2]
	if tc.ID != "tomcat" || tc.Monitored || tc.HTTPPort != 8080 || len(tc.Apps) != 2 || tc.Ports[0] != 8005 {
		t.Errorf("tomcat (not enabled in the answers = not monitored): %+v", tc)
	}
	if o := doc.Services[1]; !o.Monitored || strings.Join(o.Instances, ",") != "ORCL,TEST2" {
		t.Errorf("oracle: %+v", o)
	}
	if d := doc.Services[0]; d.Monitored || d.Ports != nil {
		t.Errorf("docker (no profile): %+v", d)
	}
	want := []InventorySocket{{"0.0.0.0", 22, ""}, {"::", 22, ""}, {"0.0.0.0", 1521, "oracle"},
		{"10.0.0.5", 8080, "tomcat"}, {"127.0.0.1", 9404, "tomcat"}}
	if len(doc.Listen) != len(want) {
		t.Fatalf("listen (sorted, ::ffff: mapped, duplicates merged): %+v", doc.Listen)
	}
	for i := range want {
		if doc.Listen[i] != want[i] {
			t.Errorf("listen[%d] = %+v, want %+v", i, doc.Listen[i], want[i])
		}
	}
	// allowlist: no paths, no pids, no other values
	for _, leak := range []string{"/opt/tomcat", "/u01", "alert_", "pids", "300", "confidence"} {
		if bytes.Contains(b, []byte(leak)) {
			t.Errorf("inventory contains %q:\n%s", leak, b)
		}
	}
	// the same host gives the same bytes (an unchanged host shows no diff, amc update does not rewrite it)
	if !bytes.Equal(b, Inventory(inventoryHost(), []string{"oracle"})) {
		t.Error("not deterministic")
	}
}

func TestInventoryCapsSockets(t *testing.T) {
	h := Host{}
	for p := 1; p <= maxSockets+10; p++ {
		h.Listen = append(h.Listen, detect.Listen{IP: "0.0.0.0", Port: p})
	}
	var doc InventoryDoc
	if err := json.Unmarshal(Inventory(h, nil), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Listen) != maxSockets || !doc.Truncated || doc.Services == nil {
		t.Errorf("cap: %d sockets, truncated %v, services %v", len(doc.Listen), doc.Truncated, doc.Services)
	}
}
