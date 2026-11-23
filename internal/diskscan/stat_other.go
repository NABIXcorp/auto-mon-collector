//go:build !linux

package diskscan

import (
	"errors"
	"io/fs"
)

// Other systems (developer machines, tests): sizes are apparent sizes, no devices, no mount list.
type stat struct {
	dev, ino uint64
	nlink    uint64
	alloc    int64
}

func statOf(fi fs.FileInfo) stat { return stat{alloc: fi.Size()} }

// LocalMounts is Linux only.
func LocalMounts() ([]MountInfo, error) { return nil, errors.New("disk scan: Linux only") }

// UsedPercent is Linux only.
func UsedPercent() (float64, string, error) { return 0, "", errors.New("disk scan: Linux only") }
