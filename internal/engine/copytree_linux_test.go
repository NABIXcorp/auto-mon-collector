//go:build linux

package engine

import (
	"os"
	"path/filepath"
	"testing"
)

// A backup / rollback copy keeps the setgid bit of config/cloudprober (root:amc-agent 2775 for the agent): before
// v0.14.0 a rollback restored it as a plain 0775 directory and the agent could no longer replace its files.
func TestCopyTreeKeepsSetgid(t *testing.T) {
	src, dst := t.TempDir(), filepath.Join(t.TempDir(), "out")
	dir := filepath.Join(src, "cloudprober")
	if err := os.Mkdir(dir, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o775|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cloudprober.cfg"), []byte("x"), 0o664); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "cloudprober.cfg"), 0o664); err != nil { // not the umask
		t.Fatal(err)
	}
	if err := copyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dst, "cloudprober"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSetgid == 0 || fi.Mode().Perm() != 0o775 {
		t.Fatalf("mode after copy: %v (want setgid + 0775)", fi.Mode())
	}
	if fi, err := os.Stat(filepath.Join(dst, "cloudprober", "cloudprober.cfg")); err != nil || fi.Mode().Perm() != 0o664 {
		t.Fatalf("file mode after copy: %v %v", fi, err)
	}
}
