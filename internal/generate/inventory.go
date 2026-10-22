package generate

import (
	"encoding/json"
	"net"
	"slices"
	"sort"
	"strconv"
)

// InventoryFile (below the prefix): the services of this host, written by plan / apply / update (root, 644), sent by
// the agent to the control plane. It is a summary on an allowlist: service ids, ports, Oracle SIDs, Tomcat context
// paths and bind addresses. No file paths, no environment, no process ids, no time stamps: the same host gives the
// same bytes, so an unchanged host shows no diff.
const InventoryFile = "inventory.json"

// InventorySchema is raised when a field changes its meaning (the control plane checks it).
const InventorySchema = 1

// maxSockets caps the listening sockets in the file (a host with thousands of ports would otherwise flood it).
const maxSockets = 256

// InventoryService is one detected service.
type InventoryService struct {
	ID        string   `json:"id"`        // oracle, tomcat, redis, caddy, nginx, postgresql, mysql, docker
	Monitored bool     `json:"monitored"` // the collector monitors it (profile + answers)
	Ports     []int    `json:"ports,omitempty"`
	HTTPPort  int      `json:"http_port,omitempty"` // tomcat
	Instances []string `json:"instances,omitempty"` // oracle SIDs
	Apps      []string `json:"apps,omitempty"`      // tomcat context paths
}

// InventorySocket is one listening TCP socket. Service = the detected service that owns the port ("" = other).
type InventorySocket struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
}

// InventoryDoc is the file format.
type InventoryDoc struct {
	Schema    int                `json:"schema"`
	OS        string             `json:"os,omitempty"`
	Services  []InventoryService `json:"services"`
	Listen    []InventorySocket  `json:"listen"`
	Truncated bool               `json:"truncated,omitempty"` // more than maxSockets sockets
}

// Inventory builds inventory.json from the scan. enabled = the monitored service ids (Output.Enabled).
func Inventory(h Host, enabled []string) []byte {
	doc := InventoryDoc{Schema: InventorySchema, OS: h.OS, Services: []InventoryService{}, Listen: []InventorySocket{}}
	owner := map[int]string{}
	for _, f := range h.Findings {
		s := InventoryService{ID: f.ID, Monitored: f.Profile && slices.Contains(enabled, f.ID),
			Ports: sortedInts(f.Ports), Instances: f.Instances, Apps: f.Apps}
		if f.ID == "tomcat" {
			s.HTTPPort, _ = strconv.Atoi(f.Values["TOMCAT_HTTP_PORT"])
		}
		for _, p := range s.Ports {
			if owner[p] == "" {
				owner[p] = f.ID
			}
		}
		doc.Services = append(doc.Services, s)
	}
	seen := map[InventorySocket]bool{}
	for _, l := range h.Listen {
		ip := l.IP
		if a := net.ParseIP(ip); a != nil {
			ip = a.String() // ::ffff:10.0.0.1 -> 10.0.0.1
		}
		s := InventorySocket{IP: ip, Port: l.Port, Service: owner[l.Port]}
		if !seen[s] {
			seen[s] = true
			doc.Listen = append(doc.Listen, s)
		}
	}
	sort.Slice(doc.Listen, func(i, j int) bool {
		a, b := doc.Listen[i], doc.Listen[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.IP < b.IP
	})
	if len(doc.Listen) > maxSockets {
		doc.Listen, doc.Truncated = doc.Listen[:maxSockets], true
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return append(b, '\n')
}

func sortedInts(xs []int) []int {
	out := slices.Clone(xs)
	sort.Ints(out)
	return out
}
