//go:build linux

package detect

import (
	"os"
	"syscall"
)

func fileGID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Gid), true
}
