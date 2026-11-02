package version

import "testing"

func TestParseAndCompare(t *testing.T) {
	for _, bad := range []string{"", "dev", "0.16.0", "v0.16", "v0.16.0-rc1", "v0.16.0+x", "v01.2.3", "v1.2.3 ", " v1.2.3",
		"v1.2.3\n", "v1.2.3/../x", "V1.2.3", "v1234567.0.0", "v1.2.3.4"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"v0.16.0", "v0.16.0", 0}, {"v0.16.0", "v0.16.1", -1}, {"v0.16.10", "v0.16.9", 1}, {"v1.0.0", "v0.99.99", 1},
		{"v0.9.0", "v0.10.0", -1}, {"v0.0.0", "v0.0.1", -1},
	} {
		a, err := Parse(c.a)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Parse(c.b)
		if err != nil {
			t.Fatal(err)
		}
		if got := Compare(a, b); got != c.want {
			t.Errorf("Compare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
		if a.String() != c.a {
			t.Errorf("String() = %s, want %s", a, c.a)
		}
	}
}
