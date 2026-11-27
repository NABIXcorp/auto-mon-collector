// Package lockfile (v0.16.0): one monitoring-agent at a time changes an installation. `apply`, `update` and
// `self-update` hold <prefix>/.monitoring.lock (flock, released by the kernel when the process ends, so a killed run
// leaves no stale lock). `self-update` hands its lock to the `update` it runs: the child inherits the locked file as
// fd 3 (EnvFD=3) and takes it over instead of waiting for its own parent.
package lockfile

import (
	"errors"
	"time"
)

// Name of the lock file below the prefix.
const Name = ".monitoring.lock"

// EnvFD: set to "3" by a parent that passes its locked file as the child's fd 3.
const EnvFD = "MONITORING_LOCK_FD"

// ErrBusy: another monitoring-agent holds the lock.
var ErrBusy = errors.New("another monitoring-agent (apply / update / self-update) is running on this installation (" + Name + "): try again when it has finished")

// AcquireWait (v0.37.1): like Acquire, but while another run holds the lock it tries again every second, up to max.
// Root's control plane jobs use it: a short periodic job (the service re-scan, the disk scan) holding the lock must
// not refuse the console's change (seen live: a settings set refused while the 15-min re-scan ran).
func AcquireWait(prefix string, max time.Duration) (*Lock, error) {
	end := time.Now().Add(max)
	for {
		l, err := Acquire(prefix)
		if !errors.Is(err, ErrBusy) || time.Now().After(end) {
			return l, err
		}
		time.Sleep(time.Second)
	}
}
