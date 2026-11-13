//go:build !unix

package lockfile

import (
	"os"
	"path/filepath"
)

// Lock: monitoring-agent installs on Linux only; elsewhere (development builds, tests) the file is created but not locked.
type Lock struct{ f *os.File }

// Acquire creates the lock file; no locking on this platform.
func Acquire(prefix string) (*Lock, error) {
	f, err := os.OpenFile(filepath.Join(prefix, Name), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	return &Lock{f}, nil
}

// File is the lock file.
func (l *Lock) File() *os.File { return l.f }

// Release closes the file.
func (l *Lock) Release() {
	if l != nil && l.f != nil {
		l.f.Close()
	}
}
