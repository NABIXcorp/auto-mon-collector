//go:build !unix

package selfupdate

import (
	"fmt"
	"os"
)

// monitoring-agent installs on Linux only; elsewhere (development builds, tests) links and owners are not checked.

func openNoFollow(p string) (*os.File, error) { return os.Open(p) }

func singleLink(os.FileInfo) bool { return true }

func rootOwned(p string, _ int) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a plain file", p)
	}
	return nil
}
