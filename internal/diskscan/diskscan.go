// Package diskscan is `monitoring-agent disk-scan` (v0.29.0): which folders and files fill each local disk, like
// `du -x` + "the biggest files", so the console can show it on the host's Disks tab without anyone logging in to
// run ncdu. It runs in its own oneshot unit monitoring-diskscan (user monitoring-agent + CAP_DAC_READ_SEARCH only,
// no network, idle IO), started by the agent. It only lists directories and stats entries: it never opens a
// regular file, never follows a symlink and never crosses into another mount. The result is one JSON file the agent
// uploads (see Result). Nothing here comes from the control plane except an opaque request id.
package diskscan

import (
	"container/heap"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Limits of one result (the control plane caps the upload at MaxResult).
const (
	MaxResult    = 256 << 10 // bytes of the JSON result
	TreeDepth    = 4         // folder levels below the mount point
	TreeChildren = 10        // biggest children kept per folder
	TreeMinShare = 0.005     // a folder below 0.5 % of the mount's used space is not listed
	TopFiles     = 20        // biggest files per mount
	MinFileSize  = 100 << 20 // a file must be at least 100 MiB to be listed
	MaxMounts    = 16        // mounts scanned at most (fullest first)
	ResultFile   = "agent/diskscan/result.json"
	TriggerFile  = "agent/diskscan/trigger.json"
)

// Node is one folder of the tree: its allocated size (bytes, like du) and its biggest children.
type Node struct {
	Name     string  `json:"name"`
	Size     int64   `json:"size"`
	Children []*Node `json:"children,omitempty"`
	More     int     `json:"more,omitempty"` // children left out (smaller than the listed ones)
}

// File is one big file.
type File struct {
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"` // unix seconds
}

// Mount is the result for one filesystem.
type Mount struct {
	Mount    string   `json:"mount"`
	FS       string   `json:"fs"`
	Size     int64    `json:"size"`    // filesystem size (statfs)
	Used     int64    `json:"used"`    // used (statfs), what the percent on the console is about
	Scanned  int64    `json:"scanned"` // what the walk found (allocated); less than Used = unreadable / excluded / deleted-but-open files
	Files    int64    `json:"files"`
	Dirs     int64    `json:"dirs"`
	Errors   int64    `json:"errors"` // folders that could not be read
	Excluded []string `json:"excluded,omitempty"`
	Partial  bool     `json:"partial,omitempty"` // the time limit ended the walk
	Tree     *Node    `json:"tree"`
	Top      []File   `json:"files_top"`
}

// Result is the file the scanner writes and the agent uploads (POST v1/diskscan).
type Result struct {
	Version   int     `json:"version"` // 1
	ID        string  `json:"id,omitempty"`
	Reason    string  `json:"reason"`               // daily | full | request
	TriggerAt int64   `json:"trigger_at,omitempty"` // the agent's trigger time: tells the agent which start this result answers
	Started   int64   `json:"started_at"`
	Finished  int64   `json:"finished_at"`
	Partial   bool    `json:"partial,omitempty"`
	Mounts    []Mount `json:"mounts"`
	Error     string  `json:"error,omitempty"`
}

// Trigger is what the agent writes before it starts the unit: why, and the console's request id (if any).
type Trigger struct {
	ID     string `json:"id,omitempty"`
	Reason string `json:"reason"`
	At     int64  `json:"at"` // unix milliseconds (the result repeats it as trigger_at)
}

// minFileSize: MinFileSize (a variable for tests).
var minFileSize int64 = MinFileSize

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// ValidID: a request id (8-64 characters A-Z a-z 0-9 _ -).
func ValidID(s string) bool { return idRE.MatchString(s) }

// ValidReason: one of the known reasons.
func ValidReason(s string) bool { return s == "daily" || s == "full" || s == "request" }

// MountInfo is one local filesystem to scan.
type MountInfo struct {
	Path string
	FS   string
	Dev  uint64
	Size int64
	Used int64
}

// Options of one scan.
type Options struct {
	Mounts  []MountInfo // nil = LocalMounts()
	Exclude []string    // absolute paths not walked (answers agent.disk_scan.exclude)
	Trigger Trigger
	Now     func() time.Time
}

// Scan walks every mount (fullest first) until ctx ends; what was not walked by then is marked partial.
func Scan(ctx context.Context, o Options) Result {
	if o.Now == nil {
		o.Now = time.Now
	}
	r := Result{Version: 1, ID: o.Trigger.ID, Reason: o.Trigger.Reason, TriggerAt: o.Trigger.At, Started: o.Now().Unix(), Mounts: []Mount{}}
	if r.Reason == "" {
		r.Reason = "daily"
	}
	ms := o.Mounts
	if ms == nil {
		var err error
		if ms, err = LocalMounts(); err != nil {
			r.Error = err.Error()
		}
	}
	sort.SliceStable(ms, func(i, j int) bool { return share(ms[i]) > share(ms[j]) })
	if len(ms) > MaxMounts {
		ms = ms[:MaxMounts]
	}
	for _, m := range ms {
		mr := scanMount(ctx, m, o.Exclude)
		r.Partial = r.Partial || mr.Partial
		r.Mounts = append(r.Mounts, mr)
	}
	r.Finished = o.Now().Unix()
	return r
}

func share(m MountInfo) float64 {
	if m.Size <= 0 {
		return 0
	}
	return float64(m.Used) / float64(m.Size)
}

type walker struct {
	ctx      context.Context
	dev      uint64
	exclude  map[string]bool
	min      int64 // smallest folder kept in the tree
	seen     map[[2]uint64]bool
	top      fileHeap
	m        *Mount
	stopped  bool
	checkCnt int
}

func scanMount(ctx context.Context, mi MountInfo, exclude []string) Mount {
	m := Mount{Mount: mi.Path, FS: mi.FS, Size: mi.Size, Used: mi.Used, Top: []File{}}
	w := &walker{ctx: ctx, dev: mi.Dev, exclude: map[string]bool{}, seen: map[[2]uint64]bool{}, m: &m}
	w.min = int64(float64(mi.Used) * TreeMinShare)
	for _, e := range exclude {
		e = filepath.Clean(e)
		sep := string(filepath.Separator)
		if e == filepath.Clean(mi.Path) || strings.HasPrefix(e, strings.TrimSuffix(filepath.Clean(mi.Path), sep)+sep) {
			w.exclude[e] = true
		}
	}
	if w.exclude[filepath.Clean(mi.Path)] {
		m.Excluded = []string{mi.Path}
		m.Tree = &Node{Name: mi.Path}
		return m
	}
	root := w.dir(mi.Path, mi.Path, 0)
	root.Name = mi.Path
	m.Tree = root
	m.Scanned = root.Size
	m.Partial = w.stopped
	sort.Sort(sort.Reverse(byFileSize(w.top)))
	m.Top = append(m.Top, w.top...)
	for e := range w.exclude {
		m.Excluded = append(m.Excluded, e)
	}
	sort.Strings(m.Excluded)
	return m
}

// dir walks one folder and returns its node (size = everything below it on this filesystem).
func (w *walker) dir(path, name string, depth int) *Node {
	n := &Node{Name: name}
	w.m.Dirs++
	if w.stop() {
		return n
	}
	ents, err := os.ReadDir(path)
	if err != nil && len(ents) == 0 {
		w.m.Errors++
		return n
	}
	if err != nil {
		w.m.Errors++ // a partly readable folder: count what was listed
	}
	var kids []*Node
	for _, e := range ents {
		p := filepath.Join(path, e.Name())
		if w.exclude[p] {
			continue
		}
		fi, err := os.Lstat(p)
		if err != nil {
			continue // gone meanwhile
		}
		st := statOf(fi)
		if st.dev != 0 && w.dev != 0 && st.dev != w.dev {
			continue // another mount (-x)
		}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			n.Size += st.alloc
		case fi.IsDir():
			c := w.dir(p, e.Name(), depth+1)
			c.Size += st.alloc
			n.Size += c.Size
			if depth < TreeDepth && c.Size >= w.min && c.Size > 0 {
				kids = append(kids, c)
			} else {
				c.Children = nil
			}
		default:
			if st.nlink > 1 {
				k := [2]uint64{st.dev, st.ino}
				if w.seen[k] {
					continue // a hard link counted once, like du
				}
				w.seen[k] = true
			}
			w.m.Files++
			n.Size += st.alloc
			if fi.Mode().IsRegular() && fi.Size() >= minFileSize {
				w.addFile(File{Path: p, Size: fi.Size(), MTime: fi.ModTime().Unix()})
			}
		}
		if w.stopped {
			break
		}
	}
	sort.Slice(kids, func(i, j int) bool { return kids[i].Size > kids[j].Size })
	if len(kids) > TreeChildren {
		n.More = len(kids) - TreeChildren
		kids = kids[:TreeChildren]
	}
	n.Children = kids
	return n
}

func (w *walker) stop() bool {
	if w.stopped {
		return true
	}
	if w.checkCnt++; w.checkCnt%64 == 0 && w.ctx.Err() != nil {
		w.stopped = true
	}
	return w.stopped
}

func (w *walker) addFile(f File) {
	if len(w.top) < TopFiles {
		heap.Push(&w.top, f)
		return
	}
	if f.Size > w.top[0].Size {
		w.top[0] = f
		heap.Fix(&w.top, 0)
	}
}

// fileHeap is a min-heap by size (the smallest of the kept files on top).
type fileHeap []File

func (h fileHeap) Len() int           { return len(h) }
func (h fileHeap) Less(i, j int) bool { return h[i].Size < h[j].Size }
func (h fileHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *fileHeap) Push(x any)        { *h = append(*h, x.(File)) }
func (h *fileHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

type byFileSize []File

func (b byFileSize) Len() int           { return len(b) }
func (b byFileSize) Less(i, j int) bool { return b[i].Size < b[j].Size }
func (b byFileSize) Swap(i, j int)      { b[i], b[j] = b[j], b[i] }

// Encode marshals the result, pruning the deepest tree level (then the file lists) until it fits MaxResult.
func Encode(r Result) ([]byte, error) {
	for depth := TreeDepth; ; depth-- {
		b, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		if len(b) <= MaxResult {
			return b, nil
		}
		if depth <= 1 {
			for i := range r.Mounts {
				if len(r.Mounts[i].Top) > 5 {
					r.Mounts[i].Top = r.Mounts[i].Top[:5]
				}
			}
			if b, err = json.Marshal(r); err == nil && len(b) <= MaxResult {
				return b, nil
			}
			return nil, fmt.Errorf("disk scan result too large (%d bytes)", len(b))
		}
		for i := range r.Mounts {
			prune(r.Mounts[i].Tree, depth-1)
		}
	}
}

// prune drops the children below the given depth (0 = keep only the node).
func prune(n *Node, depth int) {
	if n == nil {
		return
	}
	if depth <= 0 {
		n.More += len(n.Children)
		n.Children = nil
		return
	}
	for _, c := range n.Children {
		prune(c, depth-1)
	}
}

// Write saves the result as <prefix>/agent/diskscan/result.json (temp file + rename: the agent never reads half).
func Write(prefix string, r Result) error {
	b, err := Encode(r)
	if err != nil {
		return err
	}
	p := filepath.Join(prefix, filepath.FromSlash(ResultFile))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// LoadTrigger reads the agent's trigger file; missing or invalid = a daily scan without id.
func LoadTrigger(prefix string) Trigger {
	t := Trigger{Reason: "daily"}
	b, err := os.ReadFile(filepath.Join(prefix, filepath.FromSlash(TriggerFile)))
	if err != nil || len(b) > 4<<10 {
		return t
	}
	var x Trigger
	if json.Unmarshal(b, &x) != nil || !ValidReason(x.Reason) || (x.ID != "" && !ValidID(x.ID)) {
		return t
	}
	return x
}

// WriteTrigger is the agent's half: why the next scan runs.
func WriteTrigger(prefix string, t Trigger) error {
	if !ValidReason(t.Reason) || (t.ID != "" && !ValidID(t.ID)) {
		return errors.New("disk scan trigger: bad reason or id")
	}
	b, _ := json.Marshal(t)
	p := filepath.Join(prefix, filepath.FromSlash(TriggerFile))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
