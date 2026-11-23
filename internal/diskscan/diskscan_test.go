package diskscan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, p string, n int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, make([]byte, n), 0o644); err != nil {
		t.Fatal(err)
	}
}

func find(n *Node, name string) *Node {
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestScanTreeAndTopFiles(t *testing.T) {
	old := minFileSize
	minFileSize = 1000
	defer func() { minFileSize = old }()
	root := t.TempDir()
	write(t, filepath.Join(root, "u01/app/oracle/diag/trace/big.trc"), 5000000)
	write(t, filepath.Join(root, "u01/app/oracle/diag/trace/small.trc"), 10)
	write(t, filepath.Join(root, "opt/tomcat/logs/catalina.out"), 3000000)
	write(t, filepath.Join(root, "home/user/private.dmp"), 2000000)
	write(t, filepath.Join(root, "var/tiny"), 5)
	used := int64(10000000) // 0.5 % = 50 kB: above the 4 kB blocks of small files and folders (Linux)
	r := Scan(context.Background(), Options{
		Mounts:  []MountInfo{{Path: root, FS: "xfs", Size: 20000000, Used: used}},
		Exclude: []string{filepath.Join(root, "home/user")},
		Trigger: Trigger{ID: "req_12345678", Reason: "request"},
	})
	if r.Version != 1 || r.ID != "req_12345678" || r.Reason != "request" || len(r.Mounts) != 1 {
		t.Fatalf("result %+v", r)
	}
	m := r.Mounts[0]
	if m.Scanned < 8000000 || m.Partial || m.Errors != 0 {
		t.Fatalf("mount %+v", m)
	}
	u01 := find(m.Tree, "u01")
	if u01 == nil || m.Tree.Children[0].Name != "u01" {
		t.Fatalf("biggest child must be u01: %+v", m.Tree.Children)
	}
	// depth: u01 / app / oracle / diag (4 levels), not trace
	diag := find(find(find(u01, "app"), "oracle"), "diag")
	if diag == nil || len(diag.Children) != 0 {
		t.Fatalf("diag at level 4 without children: %+v", diag)
	}
	if find(m.Tree, "var") != nil {
		t.Fatal("var is below 0.5 % of used: not listed")
	}
	if h := find(m.Tree, "home"); h != nil && h.Size > 100000 {
		t.Fatalf("excluded folder counted: %+v", h)
	}
	if len(m.Excluded) != 1 || !strings.HasSuffix(filepath.ToSlash(m.Excluded[0]), "home/user") {
		t.Fatalf("excluded %v", m.Excluded)
	}
	if len(m.Top) != 2 || filepath.Base(m.Top[0].Path) != "big.trc" || filepath.Base(m.Top[1].Path) != "catalina.out" {
		t.Fatalf("top files %+v", m.Top)
	}
}

func TestScanStopsAtDeadline(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 300; i++ {
		write(t, filepath.Join(root, "d", strings.Repeat("x", 1+i%5), string(rune('a'+i%26)), "f"), 1)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := Scan(ctx, Options{Mounts: []MountInfo{{Path: root, FS: "ext4", Size: 1, Used: 1}}})
	if !r.Partial || !r.Mounts[0].Partial {
		t.Fatalf("a cancelled scan must be partial: %+v", r.Mounts[0])
	}
}

func TestEncodePrunesToFit(t *testing.T) {
	big := &Node{Name: "/"}
	for i := 0; i < 10; i++ {
		a := &Node{Name: strings.Repeat("a", 200) + string(rune('0'+i)), Size: 1}
		for j := 0; j < 10; j++ {
			b := &Node{Name: strings.Repeat("b", 200) + string(rune('0'+j)), Size: 1}
			for k := 0; k < 10; k++ {
				b.Children = append(b.Children, &Node{Name: strings.Repeat("c", 200), Size: 1})
			}
			a.Children = append(a.Children, b)
		}
		big.Children = append(big.Children, a)
	}
	r := Result{Version: 1, Mounts: []Mount{{Mount: "/", Tree: big, Top: []File{}}}}
	b, err := Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > MaxResult {
		t.Fatalf("%d bytes", len(b))
	}
	var back Result
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Mounts[0].Tree.Children) != 10 {
		t.Fatal("first level must survive pruning")
	}
}

func TestTrigger(t *testing.T) {
	dir := t.TempDir()
	if got := LoadTrigger(dir); got.Reason != "daily" || got.ID != "" {
		t.Fatalf("missing trigger = daily: %+v", got)
	}
	if err := WriteTrigger(dir, Trigger{ID: "bad id!", Reason: "request"}); err == nil {
		t.Fatal("bad id accepted")
	}
	if err := WriteTrigger(dir, Trigger{ID: "abcdefgh", Reason: "request", At: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	if got := LoadTrigger(dir); got.ID != "abcdefgh" || got.Reason != "request" {
		t.Fatalf("trigger %+v", got)
	}
	if err := Write(dir, Result{Version: 1, Reason: "daily", Mounts: []Mount{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(ResultFile))); err != nil {
		t.Fatal(err)
	}
}
