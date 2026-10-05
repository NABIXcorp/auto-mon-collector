package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	cases := []struct {
		args     []string
		code     int
		inStdout string
		inStderr string
	}{
		{[]string{"version"}, exitOK, "auto-mon-collector", ""},
		{[]string{"help"}, exitOK, "Usage:", ""},
		{nil, exitPlan, "", "not implemented"}, // default command = plan
		{[]string{"apply"}, exitPlan, "", "not implemented"},
		{[]string{"nope"}, exitUsage, "", "unknown command"},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		if got := run(c.args, &out, &errb); got != c.code {
			t.Errorf("run(%v) = %d, want %d", c.args, got, c.code)
		}
		if !strings.Contains(out.String(), c.inStdout) || !strings.Contains(errb.String(), c.inStderr) {
			t.Errorf("run(%v): stdout %q stderr %q", c.args, out.String(), errb.String())
		}
	}
}
