package selfupdate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

func marshal(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return append(b, '\n')
}

func unmarshal(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// writeRoot writes p atomically: a new temp file in the same directory (O_EXCL: never follows a link someone
// placed there, e.g. in the agent's directory), mode, owner root when we are root, then rename over p (which
// replaces a link instead of writing through it).
func writeRoot(p string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(p), ".amc-self-update-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), mode)
	}
	if err == nil && os.Geteuid() == 0 {
		err = os.Lchown(tmp.Name(), 0, 0)
	}
	if err == nil {
		err = os.Rename(tmp.Name(), p)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// readRequest reads the request the agent wrote: a regular file (no link: the agent owns that directory and must
// not make root read another file), one link only, at most maxRequest bytes.
func readRequest(p string) ([]byte, error) {
	f, err := openNoFollow(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || !singleLink(fi) {
		return nil, errors.New("not a plain file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxRequest+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxRequest {
		return nil, errors.New("too large")
	}
	return b, nil
}
