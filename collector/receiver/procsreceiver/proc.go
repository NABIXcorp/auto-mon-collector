package procsreceiver

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// userHZ is the clock tick of utime / stime / starttime in /proc/<pid>/stat. USER_HZ is 100 on every Linux build we
// target (amd64, arm64); reading AT_CLKTCK would need cgo or auxv parsing for no gain.
const userHZ = 100

type proc struct {
	pid   int
	uid   string // effective uid, like `ps -o user`
	comm  string // command NAME only (/proc/<pid>/stat field 2); /proc/<pid>/cmdline is never read: arguments can hold passwords
	ticks uint64 // utime + stime
	start uint64 // starttime, ticks after boot
	rssKB int64  // VmRSS from /proc/<pid>/status, like `ps -o rss` (0 for kernel threads)
}

// snapshot reads every process once. A process that ends while we read it is skipped.
func snapshot(procPath string) (map[int]proc, error) {
	ents, err := os.ReadDir(procPath)
	if err != nil {
		return nil, err
	}
	out := make(map[int]proc, len(ents))
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		p, err := readProc(filepath.Join(procPath, e.Name()))
		if err != nil {
			continue
		}
		p.pid = pid
		out[pid] = p
	}
	if len(out) == 0 {
		return nil, errors.New("no processes found in " + procPath)
	}
	return out, nil
}

func readProc(dir string) (proc, error) {
	var p proc
	b, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return p, err
	}
	s := string(b)
	// field 2 is "(comm)" and comm may hold spaces or ")": cut at the first "(" and the LAST ")".
	i, j := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if i < 0 || j < i {
		return p, errors.New("bad stat")
	}
	p.comm = s[i+1 : j]
	f := strings.Fields(s[j+1:]) // f[0] = field 3 (state)
	if len(f) < 20 {
		return p, errors.New("short stat")
	}
	ut, err1 := strconv.ParseUint(f[11], 10, 64) // field 14
	st, err2 := strconv.ParseUint(f[12], 10, 64) // field 15
	p.start, err = strconv.ParseUint(f[19], 10, 64)
	if err = errors.Join(err, err1, err2); err != nil {
		return p, err
	}
	p.ticks = ut + st
	p.uid, p.rssKB, err = readStatus(filepath.Join(dir, "status"))
	return p, err
}

// readStatus: effective uid and VmRSS (kB). The rss field of stat is an approximate counter on newer kernels
// (1-4 % below ps in a test on 2026-11-02); status is what ps prints.
func readStatus(statusPath string) (uid string, rssKB int64, err error) {
	fh, err := os.Open(statusPath)
	if err != nil {
		return "", 0, err
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		switch {
		case len(f) >= 3 && f[0] == "Uid:":
			uid = f[2] // real, EFFECTIVE, saved, fs
		case len(f) >= 2 && f[0] == "VmRSS:":
			rssKB, _ = strconv.ParseInt(f[1], 10, 64)
		}
	}
	if uid == "" {
		return "", 0, errors.New("no Uid line")
	}
	return uid, rssKB, nil
}

func uptimeSeconds(procPath string) (float64, error) {
	b, err := os.ReadFile(filepath.Join(procPath, "uptime"))
	if err != nil {
		return 0, err
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0, errors.New("empty uptime")
	}
	return strconv.ParseFloat(f[0], 64)
}

type row struct {
	proc
	cpu   float64 // % over the window, 100 = one core
	etime int64   // seconds since the process started
	top   string  // "cpu", "rss" or "cpu,rss"
}

// pick = the awk END block of otel-procs.sh: CPU over the window from two snapshots, then top N by CPU and top N by
// RSS (ties: lower pid first). windowS is the real time between the snapshots, uptime is taken at the second one.
func pick(a, b map[int]proc, windowS, uptime float64, top int) []row {
	rows := make([]row, 0, len(b))
	for _, p := range b {
		r := row{proc: p, etime: int64(uptime - float64(p.start)/userHZ)}
		if r.etime < 0 {
			r.etime = 0
		}
		if old, ok := a[p.pid]; ok && old.start == p.start && p.ticks >= old.ticks {
			r.cpu = float64(p.ticks-old.ticks) / userHZ * 100 / windowS
		} else if r.etime > 0 && float64(r.etime) <= windowS { // started inside the window
			r.cpu = float64(p.ticks) / userHZ * 100 / float64(r.etime)
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].pid < rows[j].pid })
	mark := func(less func(x, y row) bool, tag string) {
		idx := make([]int, len(rows))
		for i := range idx {
			idx[i] = i
		}
		sort.SliceStable(idx, func(i, j int) bool { return less(rows[idx[i]], rows[idx[j]]) })
		for k := 0; k < top && k < len(idx); k++ {
			r := &rows[idx[k]]
			if r.top == "" {
				r.top = tag
			} else {
				r.top += "," + tag
			}
		}
	}
	mark(func(x, y row) bool { return x.cpu > y.cpu }, "cpu")
	mark(func(x, y row) bool { return x.rssKB > y.rssKB }, "rss")
	out := rows[:0]
	for _, r := range rows {
		if r.top != "" {
			out = append(out, r)
		}
	}
	return out
}
