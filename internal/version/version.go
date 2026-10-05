// Package version holds build information, set at release time with
// -ldflags "-X github.com/NABIXcorp/auto-mon-collector/internal/version.Version=v0.1.0 ...".
package version

import (
	"fmt"
	"runtime"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns one line for `amc version`.
func String() string {
	return fmt.Sprintf("auto-mon-collector %s (commit %s, built %s, %s/%s)",
		Version, Commit, Date, runtime.GOOS, runtime.GOARCH)
}
