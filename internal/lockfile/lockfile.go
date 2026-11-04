// Package lockfile (v0.16.0): one monitoring-agent at a time changes an installation. `apply`, `update` and
// `self-update` hold <prefix>/.monitoring.lock (flock, released by the kernel when the process ends, so a killed run
// leaves no stale lock). `self-update` hands its lock to the `update` it runs: the child inherits the locked file as
// fd 3 (EnvFD=3) and takes it over instead of waiting for its own parent. Before v0.20.0 the names were .amc.lock and
// AMC_LOCK_FD: a child still takes over a lock passed that way (an older self-update running a newer update).
package lockfile

import "errors"

// Name of the lock file below the prefix.
const Name = ".monitoring.lock"

// LegacyName and LegacyEnvFD: the names before v0.20.0.
const (
	LegacyName  = ".amc.lock"
	LegacyEnvFD = "AMC_LOCK_FD"
)

// EnvFD: set to "3" by a parent that passes its locked file as the child's fd 3.
const EnvFD = "MONITORING_LOCK_FD"

// ErrBusy: another amc holds the lock.
var ErrBusy = errors.New("another monitoring-agent (apply / update / self-update) is running on this installation (" + Name + "): try again when it has finished")
