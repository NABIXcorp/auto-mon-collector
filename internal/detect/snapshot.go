package detect

import (
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Listen is one listening TCP socket.
type Listen struct {
	IP    string
	Port  int
	Inode string
}

// Proc is one process. Env holds ONLY the keys in envKeys: the environment of other processes can contain
// secrets, everything else is dropped right after reading.
type Proc struct {
	PID    int
	Comm   string
	Args   []string
	Ports  []int // listening ports owned by this process
	Env    map[string]string
	inodes map[string]bool
}

// Snapshot is what detection reads from the host, once.
type Snapshot struct {
	OS      string
	Listens []Listen
	Procs   []Proc
	Notes   []string // e.g. "not root: process details incomplete"
}

var envKeys = map[string]bool{"ORACLE_BASE": true, "ORACLE_HOME": true, "ORACLE_SID": true,
	"CATALINA_BASE": true, "CATALINA_HOME": true}

// Collect reads /proc/net/tcp{,6} and /proc/<pid>/{comm,cmdline,fd,environ}.
func Collect(s Source) Snapshot {
	var snap Snapshot
	if b, err := s.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
				snap.OS = strings.Trim(v, `"'`)
			}
		}
	}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := s.ReadFile(f)
		if err != nil {
			continue
		}
		snap.Listens = append(snap.Listens, parseTCP(string(b))...)
	}
	byInode := map[string]Listen{}
	for _, l := range snap.Listens {
		byInode[l.Inode] = l
	}
	names, _ := s.ReadDir("/proc")
	hidden := 0
	for _, n := range names {
		pid, err := strconv.Atoi(n)
		if err != nil {
			continue
		}
		base := "/proc/" + n
		p := Proc{PID: pid, inodes: map[string]bool{}}
		if b, err := s.ReadFile(base + "/comm"); err == nil {
			p.Comm = strings.TrimSpace(string(b))
		}
		if b, err := s.ReadFile(base + "/cmdline"); err == nil {
			for _, a := range strings.Split(strings.TrimRight(string(b), "\x00"), "\x00") {
				if a != "" {
					p.Args = append(p.Args, a)
				}
			}
		}
		if p.Comm == "" && len(p.Args) == 0 {
			continue // kernel thread or gone
		}
		fds, err := s.ReadDir(base + "/fd")
		if err != nil {
			hidden++
		}
		for _, fd := range fds {
			t, err := s.Readlink(base + "/fd/" + fd)
			if inode, ok := strings.CutPrefix(t, "socket:["); err == nil && ok {
				inode = strings.TrimSuffix(inode, "]")
				if l, listening := byInode[inode]; listening {
					p.inodes[inode] = true
					p.Ports = appendUnique(p.Ports, l.Port)
				}
			}
		}
		sort.Ints(p.Ports)
		if b, err := s.ReadFile(base + "/environ"); err == nil {
			for _, kv := range strings.Split(string(b), "\x00") {
				if k, v, ok := strings.Cut(kv, "="); ok && envKeys[k] {
					if p.Env == nil {
						p.Env = map[string]string{}
					}
					p.Env[k] = v
				}
			}
		}
		snap.Procs = append(snap.Procs, p)
	}
	if hidden > 0 {
		snap.Notes = append(snap.Notes, fmt.Sprintf("%d process(es) not readable: run as root for full results", hidden))
	}
	return snap
}

// parseTCP reads the listening sockets (state 0A) of /proc/net/tcp or tcp6.
func parseTCP(text string) []Listen {
	var out []Listen
	for i, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if i == 0 || len(f) < 10 || f[3] != "0A" {
			continue
		}
		ipHex, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}
		out = append(out, Listen{IP: hexIP(ipHex), Port: int(port), Inode: f[9]})
	}
	return out
}

// hexIP decodes the kernel's address format: 32-bit words in host (little-endian) order.
func hexIP(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return h
	}
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return net.IP(b).String()
}

func appendUnique(xs []int, x int) []int {
	for _, v := range xs {
		if v == x {
			return xs
		}
	}
	return append(xs, x)
}

// PortsListening returns every listening port (any process), sorted.
func (s Snapshot) PortsListening() []int {
	var ps []int
	for _, l := range s.Listens {
		ps = appendUnique(ps, l.Port)
	}
	sort.Ints(ps)
	return ps
}
