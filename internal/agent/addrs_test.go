package agent

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/NABIXcorp/auto-mon-collector/assets"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

// v0.28.0: the host's IPs: private / public, no container bridges, link-local or duplicates, IPv4 first, stable order
func TestClassifyAddrs(t *testing.T) {
	a := func(n, ip string) ifAddr { return ifAddr{name: n, ip: netip.MustParseAddr(ip)} }
	got := classify([]ifAddr{
		a("eth0", "2001:db8::5"), a("eth0", "203.0.113.5"), a("ens10", "10.0.0.5"), a("docker0", "172.17.0.1"),
		a("veth12ab", "172.18.0.1"), a("eth0", "fe80::1"), a("tailscale0", "100.100.1.2"), a("eth1", "192.168.1.20"),
		a("eth0", "203.0.113.5"), a("eth0", "169.254.1.1"),
	})
	want := []InvAddress{{"private", "10.0.0.5", "ens10"}, {"public", "203.0.113.5", "eth0"}, {"private", "192.168.1.20", "eth1"},
		{"private", "100.100.1.2", "tailscale0"}, {"public", "2001:db8::5", "eth0"}}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%d: got %+v want %+v (all %+v)", i, got[i], want[i], got)
		}
	}
}

func TestInventoryAddresses(t *testing.T) {
	old := hostAddrs
	defer func() { hostAddrs = old }()
	hostAddrs = func() []InvAddress { return []InvAddress{{Kind: "private", Address: "10.0.0.5", Interface: "ens10"}} }
	body, _ := inventoryBody(t.TempDir(), nil, 1, false, false, generate.Allow{}, generate.AgentAllowEdit{}, false, false)
	var inv struct {
		Addresses []InvAddress `json:"addresses"`
	}
	if err := json.Unmarshal(body, &inv); err != nil || len(inv.Addresses) != 1 || inv.Addresses[0].Address != "10.0.0.5" {
		t.Fatalf("addresses: %s (%v)", body, err)
	}
}

// v0.28.1: the agent unit lets the agent read the interface list (netlink); v0.28.0 sent no addresses without it
func TestAgentUnitAllowsNetlink(t *testing.T) {
	b, err := assets.Unit(assets.AgentUnit, assets.UnitData{Prefix: "/opt/monitoring", User: "monitoring"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n") || !strings.Contains(string(b), "CapabilityBoundingSet=\n") {
		t.Fatalf("agent unit:\n%s", b)
	}
}
