//go:build unix

package selfupdate

import (
	"fmt"
	"os"
	"syscall"
)

// openNoFollow opens p for reading; a symbolic link (as the last element) is an error, not followed.
func openNoFollow(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

func singleLink(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Nlink == 1
}

// rootOwned: p is a regular file owned by uid that nobody else may write (answers.yaml holds the pinned key and
// the update policy: only root may change them).
func rootOwned(p string, uid int) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return fmt.Errorf("%s is not a plain file", p)
	case !ok || int(st.Uid) != uid:
		return fmt.Errorf("%s is not owned by uid %d", p, uid)
	case fi.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%s is writable by group or others (mode %o)", p, fi.Mode().Perm())
	}
	return nil
}
