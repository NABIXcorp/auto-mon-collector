package agent

import (
	"net"
	"net/netip"
	"sort"
	"strings"
)

// hostAddrs (v0.28.0): the host's IPs for the inventory; a variable so tests can swap it. It needs AF_NETLINK in the
// agent unit (v0.28.1): without it net.Interfaces fails and the inventory has no addresses.
var hostAddrs = func() []InvAddress {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var in []ifAddr
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		as, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range as {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				in = append(in, ifAddr{name: i.Name, ip: p.Addr()})
			}
		}
	}
	return classify(in)
}

type ifAddr struct {
	name string
	ip   netip.Addr
}

// container / virtual bridges: their addresses are not ways to reach the host from another host
var virtualIf = []string{"docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "vxlan", "kube", "podman", "lxc", "lxd"}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// maxAddrs: a host with more addresses sends the first ones (IPv4 first)
const maxAddrs = 16

// classify: keep global unicast addresses of real interfaces, kind private / public, IPv4 first, then by interface
// and address (a stable order: the inventory is sent again only when its hash changes).
func classify(in []ifAddr) []InvAddress {
	var out []InvAddress
	seen := map[netip.Addr]bool{}
	for _, x := range in {
		ip := x.ip.Unmap()
		if virtual(x.name) || !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() || seen[ip] {
			continue
		}
		seen[ip] = true
		kind := "public"
		if ip.IsPrivate() || cgnat.Contains(ip) {
			kind = "private"
		}
		out = append(out, InvAddress{Kind: kind, Address: ip.String(), Interface: x.name})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := netip.MustParseAddr(out[i].Address), netip.MustParseAddr(out[j].Address)
		if a.Is4() != b.Is4() {
			return a.Is4()
		}
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		return a.Less(b)
	})
	if len(out) > maxAddrs {
		out = out[:maxAddrs]
	}
	return out
}

func virtual(name string) bool {
	for _, p := range virtualIf {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
