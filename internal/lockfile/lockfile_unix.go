//go:build unix

package lockfile

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// Lock is a held lock.
type Lock struct{ f *os.File }

// Acquire takes the lock of the installation below prefix without waiting (ErrBusy when another amc holds it).
func Acquire(prefix string) (*Lock, error) {
	p := filepath.Join(prefix, Name)
	if os.Getenv(EnvFD) == "3" {
		os.Unsetenv(EnvFD) // not passed on to our own children
		if l := inherited(p); l != nil {
			return l, nil
		}
	}
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, err
	}
	return &Lock{f}, nil
}

// inherited: fd 3 is the lock file of THIS installation and already locked by our parent (same open file, so the
// flock succeeds at once). Anything else on fd 3 is left alone.
func inherited(p string) *Lock {
	var st syscall.Stat_t
	if syscall.Fstat(3, &st) != nil {
		return nil
	}
	pi, err := os.Stat(p)
	if err != nil {
		return nil
	}
	ps, ok := pi.Sys().(*syscall.Stat_t)
	if !ok || ps.Dev != st.Dev || ps.Ino != st.Ino {
		return nil
	}
	if syscall.Flock(3, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil
	}
	syscall.CloseOnExec(3)
	return &Lock{os.NewFile(3, p)}
}

// File is the locked file (passed to a child as fd 3, see EnvFD).
func (l *Lock) File() *os.File { return l.f }

// Release unlocks (closing the file releases the flock).
func (l *Lock) Release() {
	if l != nil && l.f != nil {
		l.f.Close()
	}
}
