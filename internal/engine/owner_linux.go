//go:build linux

package engine

import (
	"fmt"
	"os"
	"syscall"
)

// rootOnly600 reports whether a secrets file is owned by rootUID (0 in production) with mode 600.
func rootOnly600(fi os.FileInfo, rootUID int) (bool, string) {
	uid, _ := ownerUID(fi)
	return uid == rootUID && fi.Mode().Perm() == 0o600, fmt.Sprintf("uid %d, mode %o", uid, fi.Mode().Perm())
}

// ownerUID returns the numeric owner of a file.
func ownerUID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
