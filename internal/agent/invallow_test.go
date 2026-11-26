package agent

import (
	"encoding/json"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

// v0.25.0: the inventory carries the effective allowlist; empty lists are [] (not null) so "none" differs from
// "an older agent that does not send it"
func TestInventoryAllow(t *testing.T) {
	body, _ := inventoryBody(t.TempDir(), nil, 3, false, false, generate.Allow{Domains: []string{"*.example.com"}, Ports: []int{443}, MaxProbes: 30, MinIntervalS: 15}, generate.AgentAllowEdit{}, false, false, false, nil, false)
	var inv struct {
		Allow *struct {
			Domains  []string `json:"domains"`
			Networks []string `json:"networks"`
			Ports    []int    `json:"ports"`
			Ping     bool     `json:"ping"`
			Max      int      `json:"max_probes"`
		} `json:"allow"`
	}
	if err := json.Unmarshal(body, &inv); err != nil || inv.Allow == nil {
		t.Fatalf("no allow in %s (%v)", body, err)
	}
	a := inv.Allow
	if len(a.Domains) != 1 || a.Domains[0] != "*.example.com" || len(a.Ports) != 1 || a.Ports[0] != 443 || a.Networks == nil || a.Ping || a.Max != 30 {
		t.Fatalf("allow: %+v (%s)", a, body)
	}
}
