//go:build unix

package lockfile

import (
	"errors"
	"os"
	"os/exec"
	"testing"
)

func TestBusyAndRelease(t *testing.T) {
	dir := t.TempDir()
	a, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(dir); !errors.Is(err, ErrBusy) { // another open file = another lock, even in one process
		t.Fatalf("second lock: %v", err)
	}
	a.Release()
	b, err := Acquire(dir)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	b.Release()
}

// The child of a lock holder takes the lock over only through the inherited fd 3 (self-update -> amc update);
// without it, it is refused like any other amc.
func TestInheritedLock(t *testing.T) {
	if dir := os.Getenv("AMC_LOCK_TEST_DIR"); dir != "" { // the child
		l, err := Acquire(dir)
		if err != nil {
			os.Exit(3)
		}
		l.Release()
		os.Exit(0)
	}
	dir := t.TempDir()
	l, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	child := func(pass bool) error {
		cmd := exec.Command(os.Args[0], "-test.run=^TestInheritedLock$")
		cmd.Env = append(os.Environ(), "AMC_LOCK_TEST_DIR="+dir)
		if pass {
			cmd.ExtraFiles = []*os.File{l.File()}
			cmd.Env = append(cmd.Env, EnvFD+"=3")
		}
		return cmd.Run()
	}
	if err := child(true); err != nil {
		t.Errorf("child with the inherited lock: %v", err)
	}
	if err := child(false); err == nil {
		t.Error("child without the inherited lock got it")
	}
	// fd 3 is some other file: not taken as the lock
	other, _ := os.CreateTemp(dir, "other")
	defer other.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestInheritedLock$")
	cmd.Env = append(os.Environ(), "AMC_LOCK_TEST_DIR="+dir, EnvFD+"=3")
	cmd.ExtraFiles = []*os.File{other}
	if cmd.Run() == nil {
		t.Error("a foreign fd 3 was accepted as the lock")
	}
}
