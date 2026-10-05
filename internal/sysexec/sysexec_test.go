//go:build linux

package sysexec

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTimedStopsAtTheLimit(t *testing.T) {
	t0 := time.Now()
	out, err := Runner{}.Timed(context.Background(), nil, 500*time.Millisecond, nil,
		"sh", "-c", "echo started; sleep 30")
	if err != nil || !strings.Contains(string(out), "started") {
		t.Fatalf("out %q err %v", out, err)
	}
	if time.Since(t0) > 5*time.Second {
		t.Errorf("took %s", time.Since(t0))
	}
}

func TestTimedEarlyStopAndExit(t *testing.T) {
	out, err := Runner{}.Timed(context.Background(), nil, 30*time.Second,
		func(l string) bool { return strings.Contains(l, "ORA-01017") },
		"sh", "-c", "echo ORA-01017; sleep 30")
	if err != nil || !strings.Contains(string(out), "ORA-01017") {
		t.Fatalf("early stop: out %q err %v", out, err)
	}
	if _, err := (Runner{}).Timed(context.Background(), nil, 30*time.Second, nil, "sh", "-c", "exit 3"); err == nil {
		t.Error("a program that exits by itself must return an error")
	}
}
