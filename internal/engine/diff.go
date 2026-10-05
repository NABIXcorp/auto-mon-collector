package engine

import (
	"fmt"
	"strings"
)

// lineDiff returns a short unified-style diff (2 lines of context) and the number of added / removed lines.
// Inputs are config files of a few hundred lines, so a simple LCS table is fast enough and has no dependency.
func lineDiff(oldText, newText string) (out string, added, removed int) {
	a := strings.Split(strings.TrimRight(oldText, "\n"), "\n")
	b := strings.Split(strings.TrimRight(newText, "\n"), "\n")
	n, m := len(a), len(b)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	type op struct {
		kind byte // ' ', '-', '+'
		text string
		ln   int // line number in the new file (old file for '-')
	}
	var ops []op
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && a[i] == b[j]:
			ops = append(ops, op{' ', a[i], j + 1})
			i, j = i+1, j+1
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]): // removals first, like diff -u
			ops = append(ops, op{'-', a[i], i + 1})
			removed++
			i++
		default:
			ops = append(ops, op{'+', b[j], j + 1})
			added++
			j++
		}
	}
	const ctx = 2
	var sb strings.Builder
	last := -1
	for k, o := range ops {
		if o.kind == ' ' {
			continue
		}
		from := max(k-ctx, last+1)
		if last >= 0 && from > last+1 {
			sb.WriteString("@@\n")
		} else if last < 0 {
			fmt.Fprintf(&sb, "@@ line %d\n", ops[from].ln)
		}
		for c := from; c < k; c++ {
			sb.WriteString(" " + ops[c].text + "\n")
		}
		sb.WriteString(string(o.kind) + o.text + "\n")
		last = k
		for c := k + 1; c < len(ops) && c <= k+ctx && ops[c].kind == ' '; c++ {
			sb.WriteString(" " + ops[c].text + "\n")
			last = c
		}
	}
	return sb.String(), added, removed
}
