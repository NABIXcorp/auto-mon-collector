//go:build linux

package diskscan

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type stat struct {
	dev, ino uint64
	nlink    uint64
	alloc    int64 // allocated bytes (st_blocks * 512), what du counts
}

func statOf(fi fs.FileInfo) stat {
	s, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return stat{alloc: fi.Size()}
	}
	return stat{dev: uint64(s.Dev), ino: s.Ino, nlink: uint64(s.Nlink), alloc: s.Blocks * 512}
}

// localFS: filesystems on local disks. Not: tmpfs, overlay (containers), network filesystems, proc / sys / cgroup.
var localFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true,
	"f2fs": true, "jfs": true, "reiserfs": true, "vfat": true, "exfat": true}

// LocalMounts lists the local filesystems from /proc/self/mountinfo: one entry per device (a bind mount or a
// second mount of the same device is skipped), with size and used space from statfs.
func LocalMounts() ([]MountInfo, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	seen := map[string]bool{}
	var out []MountInfo
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
		left, right, ok := strings.Cut(sc.Text(), " - ")
		if !ok {
			continue
		}
		lf, rf := strings.Fields(left), strings.Fields(right)
		if len(lf) < 5 || len(rf) < 1 || !localFS[rf[0]] || lf[3] != "/" || seen[lf[2]] {
			continue
		}
		mp := unescape(lf[4])
		var s syscall.Statfs_t
		if syscall.Statfs(mp, &s) != nil {
			continue
		}
		var st syscall.Stat_t
		if syscall.Stat(mp, &st) != nil {
			continue
		}
		seen[lf[2]] = true
		bs := int64(s.Bsize)
		size := int64(s.Blocks) * bs
		used := (int64(s.Blocks) - int64(s.Bfree)) * bs
		out = append(out, MountInfo{Path: mp, FS: rf[0], Dev: uint64(st.Dev), Size: size, Used: used})
	}
	return out, sc.Err()
}

// unescape reads the octal escapes of mountinfo (\040 = space).
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// UsedPercent: the fullest local mount in percent (statfs only, cheap: the agent checks it every poll).
func UsedPercent() (float64, string, error) {
	ms, err := LocalMounts()
	if err != nil {
		return 0, "", err
	}
	best, at := 0.0, ""
	for _, m := range ms {
		if p := share(m) * 100; p > best {
			best, at = p, m.Path
		}
	}
	if at == "" {
		return 0, "", fmt.Errorf("no local filesystem found")
	}
	return best, at, nil
}
