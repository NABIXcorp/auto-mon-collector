// Package detect finds services on a Linux host by reading /proc and the filesystem (read-only).
//
// Everything goes through a Source, so tests can describe a whole host in memory (works on any OS).
package detect

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Source is read-only access to a host's filesystem. Paths are absolute, slash-separated.
type Source interface {
	ReadFile(p string) ([]byte, error)
	ReadDir(p string) ([]string, error) // entry names, sorted
	Readlink(p string) (string, error)
	Glob(pattern string) ([]string, error)
	Group(p string) (string, error) // name of the file's group (from /etc/group)
}

// OS is the real host below Root ("" = /).
type OS struct{ Root string }

func (o OS) fs(p string) string { return filepath.Join(o.Root, filepath.FromSlash(p)) }

func (o OS) ReadFile(p string) ([]byte, error) { return os.ReadFile(o.fs(p)) }

func (o OS) ReadDir(p string) ([]string, error) {
	entries, err := os.ReadDir(o.fs(p))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

func (o OS) Readlink(p string) (string, error) { return os.Readlink(o.fs(p)) }

func (o OS) Glob(pattern string) ([]string, error) {
	m, err := filepath.Glob(o.fs(pattern))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(m))
	for _, p := range m {
		rel, err := filepath.Rel(o.fs("/"), p)
		if err != nil {
			continue
		}
		out = append(out, "/"+filepath.ToSlash(rel))
	}
	sort.Strings(out)
	return out, nil
}

func (o OS) Group(p string) (string, error) {
	fi, err := os.Stat(o.fs(p))
	if err != nil {
		return "", err
	}
	gid, ok := fileGID(fi)
	if !ok {
		return "", fs.ErrInvalid
	}
	return groupName(o, gid), nil
}

// groupName resolves a gid from <root>/etc/group ("" if unknown).
func groupName(s Source, gid int) string {
	b, _ := s.ReadFile("/etc/group")
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, ":")
		if len(f) >= 3 && f[2] == strconv.Itoa(gid) {
			return f[0]
		}
	}
	return ""
}

// Mem is an in-memory host for tests: Files (content), Links (symlink targets), Groups (file -> group).
type Mem struct {
	Files  map[string]string
	Links  map[string]string
	Groups map[string]string
}

func (m Mem) ReadFile(p string) ([]byte, error) {
	if s, ok := m.Files[p]; ok {
		return []byte(s), nil
	}
	return nil, fs.ErrNotExist
}

func (m Mem) ReadDir(p string) ([]string, error) {
	p = strings.TrimSuffix(p, "/") + "/"
	seen := map[string]bool{}
	for _, all := range []map[string]string{m.Files, m.Links} {
		for k := range all {
			if strings.HasPrefix(k, p) {
				seen[strings.SplitN(k[len(p):], "/", 2)[0]] = true
			}
		}
	}
	if len(seen) == 0 {
		return nil, fs.ErrNotExist
	}
	var out []string
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func (m Mem) Readlink(p string) (string, error) {
	if t, ok := m.Links[p]; ok {
		return t, nil
	}
	return "", fs.ErrNotExist
}

func (m Mem) Glob(pattern string) ([]string, error) {
	var out []string
	for k := range m.Files {
		if ok, _ := path.Match(pattern, k); ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m Mem) Group(p string) (string, error) {
	if g, ok := m.Groups[p]; ok {
		return g, nil
	}
	return "", fs.ErrNotExist
}
