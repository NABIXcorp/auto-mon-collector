package version

import (
	"fmt"
	"regexp"
	"strconv"
)

// releaseRE: a release tag exactly as the release workflow builds it (v0.16.0). No pre-release / build suffix, no
// leading zeros: the string goes into a download URL and a file name, so nothing else is accepted.
var releaseRE = regexp.MustCompile(`^v(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)

// Semver is a parsed release tag.
type Semver [3]int

// Parse reads a release tag "vMAJOR.MINOR.PATCH" (v0.16.0 in self-update). Anything else is an error.
func Parse(s string) (Semver, error) {
	m := releaseRE.FindStringSubmatch(s)
	if m == nil {
		return Semver{}, fmt.Errorf("version %q: want a release tag like v1.2.3", s)
	}
	var v Semver
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1]) // at most 6 digits: no overflow
	}
	return v, nil
}

// Compare: -1 when a < b, 0 when equal, 1 when a > b.
func Compare(a, b Semver) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

func (v Semver) String() string { return fmt.Sprintf("v%d.%d.%d", v[0], v[1], v[2]) }
