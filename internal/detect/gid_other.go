//go:build !linux

package detect

import "os"

// fileGID: amc detects on Linux only; elsewhere (tests on a developer machine) groups are unknown.
func fileGID(os.FileInfo) (int, bool) { return 0, false }
