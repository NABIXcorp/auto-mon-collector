package netconnreceiver

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// /proc/net/tcp state codes (include/net/tcp_states.h).
const (
	stEstab     = "01"
	stTimeWait  = "06"
	stCloseWait = "08"
	stListen    = "0A"
)

type sock struct {
	lport, rport int
	state        string
}

// readSockets parses <proc>/net/tcp and tcp6 (same table `ss -tan` prints). LISTEN sockets are skipped, like the script does.
func readSockets(procPath string) ([]sock, error) {
	var out []sock
	found := false
	for _, f := range []string{"tcp", "tcp6"} {
		fh, err := os.Open(filepath.Join(procPath, "net", f))
		if err != nil {
			if os.IsNotExist(err) && f == "tcp6" { // IPv6 disabled
				continue
			}
			return nil, err
		}
		found = true
		sc := bufio.NewScanner(fh)
		sc.Scan() // header
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) < 4 || strings.EqualFold(fs[3], stListen) {
				continue
			}
			lp, ok1 := hexPort(fs[1])
			rp, ok2 := hexPort(fs[2])
			if !ok1 || !ok2 {
				continue
			}
			out = append(out, sock{lp, rp, strings.ToUpper(fs[3])})
		}
		fh.Close()
	}
	if !found {
		return nil, os.ErrNotExist
	}
	return out, nil
}

func hexPort(addr string) (int, bool) {
	i := strings.LastIndexByte(addr, ':')
	if i < 0 {
		return 0, false
	}
	v, err := strconv.ParseUint(addr[i+1:], 16, 32)
	return int(v), err == nil
}

type counts struct{ established, closeWait, timeWait, other int }

// aggregate = the awk block of the script: per watched port and direction ("in": local port, "out": remote port).
func aggregate(socks []sock, ports []int) map[[2]string]counts {
	watch := map[int]bool{}
	for _, p := range ports {
		watch[p] = true
	}
	res := map[[2]string]counts{}
	add := func(port int, dir, st string) {
		k := [2]string{strconv.Itoa(port), dir}
		c := res[k]
		switch st {
		case stEstab:
			c.established++
		case stCloseWait:
			c.closeWait++
		case stTimeWait:
			c.timeWait++
		default:
			c.other++
		}
		res[k] = c
	}
	for _, s := range socks {
		if watch[s.lport] {
			add(s.lport, "in", s.state)
		}
		if watch[s.rport] {
			add(s.rport, "out", s.state)
		}
	}
	return res
}
