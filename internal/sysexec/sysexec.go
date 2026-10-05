// Package sysexec is the real engine.Runner: it runs system tools with os/exec. Commands get an explicit,
// minimal environment when one is given (validate receives the secrets that way, never as arguments).
package sysexec

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Runner runs commands on the local system.
type Runner struct{}

// Run executes name with args; the error is non-nil for a non-zero exit or a missing tool.
func (Runner) Run(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

// Output executes name and returns stdout + stderr. env == nil inherits amc's environment.
func (Runner) Output(env []string, name string, args ...string) ([]byte, error) {
	c := exec.Command(name, args...)
	if env != nil {
		c.Env = env
	}
	return c.CombinedOutput()
}

// LookPath reports whether a tool is installed.
func (Runner) LookPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Timed runs a long-running program for at most d and returns its output. It stops early when stop(line)
// is true for an output line. Stopping = SIGTERM, then SIGKILL after 10 s (a collector that hangs in its
// shutdown must not hang amc). The error is nil when amc stopped the program (time limit, early stop,
// cancel) and non-nil when it could not start or exited by itself.
func (Runner) Timed(ctx context.Context, env []string, d time.Duration, stop func(string) bool,
	name string, args ...string) ([]byte, error) {
	c := exec.Command(name, args...)
	c.Env = env
	// A child of the program can keep the output pipe open after the program itself is gone; Wait would
	// then block until that child ends (CI test: 30 s instead of 0.5 s). WaitDelay bounds that wait.
	c.WaitDelay = 2 * time.Second
	pr, pw := io.Pipe()
	c.Stdout, c.Stderr = pw, pw
	if err := c.Start(); err != nil {
		return nil, err
	}
	var (
		mu  sync.Mutex
		out bytes.Buffer
	)
	early := make(chan struct{}, 1)
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			mu.Lock()
			out.Write(sc.Bytes())
			out.WriteByte('\n')
			mu.Unlock()
			if stop != nil && stop(sc.Text()) {
				select {
				case early <- struct{}{}:
				default:
				}
			}
		}
	}()
	done := make(chan error, 1)
	go func() { done <- c.Wait(); pw.Close() }()
	var err error
	select {
	case err = <-done: // exited by itself (usually a start error)
		if err == nil {
			err = errExited
		}
	case <-time.After(d):
		err = terminate(c, done)
	case <-early:
		err = terminate(c, done)
	case <-ctx.Done():
		err = terminate(c, done)
	}
	time.Sleep(100 * time.Millisecond) // let the reader drain the last lines
	mu.Lock()
	defer mu.Unlock()
	return append([]byte(nil), out.Bytes()...), err
}

var errExited = errors.New("exited by itself before the time limit")

func terminate(c *exec.Cmd, done chan error) error {
	_ = c.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = c.Process.Kill()
		<-done
	}
	return nil
}
