// Package sysexec is the real engine.Runner: it runs system tools with os/exec. Commands get an explicit,
// minimal environment when one is given (validate receives the secrets that way, never as arguments).
package sysexec

import (
	"os/exec"
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
