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

// keepOwner gives dst the owner of src (backup / rollback copies: the agent's config/cloudprober is root:amc-agent).
// Only as root; a normal user (tests) cannot chown.
func keepOwner(src os.FileInfo, dst string) error {
	st, ok := src.Sys().(*syscall.Stat_t)
	if !ok || os.Geteuid() != 0 {
		return nil
	}
	return os.Lchown(dst, int(st.Uid), int(st.Gid))
}

// ownedBy: uid / gid of a file are these. Only checked when amc runs as root (tests run as a normal user in a
// temp dir: owners cannot be set there).
func ownedBy(fi os.FileInfo, uid, gid int) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || os.Geteuid() != 0 {
		return true
	}
	return int(st.Uid) == uid && int(st.Gid) == gid
}
