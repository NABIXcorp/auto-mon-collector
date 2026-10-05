package version

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	s := String()
	for _, want := range []string{"auto-mon-collector", Version, Commit} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, missing %q", s, want)
		}
	}
}
