package engine

import (
	"fmt"
	"io"
	"strings"
)

// report prints the same line format as the original install.sh, so operators see one style:
//
//	== 3. secrets
//	  ok    ...      (state is fine)       would: ...  (check mode: would change)
//	  done  ...      (apply: changed)      WARN  / FAIL
type report struct {
	w                  io.Writer
	failures, warnings int
}

func (r *report) step(format string, a ...any) { fmt.Fprintf(r.w, "\n== "+format+"\n", a...) }
func (r *report) ok(format string, a ...any)   { fmt.Fprintf(r.w, "  ok    "+format+"\n", a...) }
func (r *report) would(format string, a ...any) {
	fmt.Fprintf(r.w, "  would: "+format+"\n", a...)
}
func (r *report) done(format string, a ...any) { fmt.Fprintf(r.w, "  done  "+format+"\n", a...) }
func (r *report) line(format string, a ...any) { fmt.Fprintf(r.w, "  "+format+"\n", a...) }
func (r *report) warn(format string, a ...any) {
	r.warnings++
	fmt.Fprintf(r.w, "  WARN  "+format+"\n", a...)
}
func (r *report) fail(format string, a ...any) {
	r.failures++
	fmt.Fprintf(r.w, "  FAIL  "+format+"\n", a...)
}

// indent prints a block (diff, tool output) under the current line, at most max lines.
func (r *report) indent(text string, max int) {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	for i, l := range lines {
		if i == max {
			fmt.Fprintf(r.w, "        ... %d more lines\n", len(lines)-max)
			return
		}
		fmt.Fprintf(r.w, "        %s\n", l)
	}
}
