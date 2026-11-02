// Package lockfile (v0.16.0): one amc at a time changes an installation. `amc apply`, `amc update` and
// `amc self-update` hold <prefix>/.amc.lock (flock, released by the kernel when the process ends, so a killed run
// leaves no stale lock). `amc self-update` hands its lock to the `amc update` it runs: the child inherits the locked
// file as fd 3 (EnvFD=3) and takes it over instead of waiting for its own parent.
package lockfile

import "errors"

// Name of the lock file below the prefix.
const Name = ".amc.lock"

// EnvFD: set to "3" by a parent that passes its locked file as the child's fd 3.
const EnvFD = "AMC_LOCK_FD"

// ErrBusy: another amc holds the lock.
var ErrBusy = errors.New("another amc (apply / update / self-update) is running on this installation (" + Name + "): try again when it has finished")
