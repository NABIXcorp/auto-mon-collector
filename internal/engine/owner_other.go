//go:build !linux

package engine

import "os"

// ownerUID: amc only runs on Linux; on other systems (developer machines running the tests) every file
// counts as owned by root.
func ownerUID(os.FileInfo) (int, bool) { return 0, true }

// rootOnly600: Unix modes do not exist there, so the check passes (it is enforced on Linux).
func rootOnly600(os.FileInfo) (bool, string) { return true, "not checked on this OS" }
