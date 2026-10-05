// Package ask asks the operator what a scan cannot know (docs/design.md, sections 4.3 / 4.4 / 6a).
// Every question has a default (Enter = default); secrets are read without echo and never printed.
package ask

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// Prompter talks to the operator.
type Prompter interface {
	Say(format string, a ...any)
	Ask(question, def string) (string, error) // empty answer = def
	YesNo(question string, def bool) (bool, error)
	Secret(question string) (string, error) // no echo
}

// ErrNoTerminal: there is nobody to ask (automation, CI, cron).
var ErrNoTerminal = errors.New("no terminal to ask on (give --answers FILE)")

// TTY asks on /dev/tty, so it also works when stdin is a pipe (curl ... | bash).
type TTY struct {
	f *os.File
	r *bufio.Reader
}

// OpenTTY returns ErrNoTerminal when there is no controlling terminal.
func OpenTTY() (*TTY, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil || !term.IsTerminal(int(f.Fd())) {
		if f != nil {
			f.Close()
		}
		return nil, ErrNoTerminal
	}
	return &TTY{f: f, r: bufio.NewReader(f)}, nil
}

func (t *TTY) Close() error { return t.f.Close() }

func (t *TTY) Say(format string, a ...any) { fmt.Fprintf(t.f, format, a...) }

func (t *TTY) line() (string, error) {
	s, err := t.r.ReadString('\n')
	if err != nil && s == "" {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

func (t *TTY) Ask(question, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(t.f, "%s [%s]: ", question, def)
	} else {
		fmt.Fprintf(t.f, "%s: ", question)
	}
	s, err := t.line()
	if err != nil {
		return "", err
	}
	if s == "" {
		return def, nil
	}
	return s, nil
}

func (t *TTY) YesNo(question string, def bool) (bool, error) {
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	for {
		fmt.Fprintf(t.f, "%s %s ", question, hint)
		s, err := t.line()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(s) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Fprintln(t.f, "  please answer y or n")
	}
}

func (t *TTY) Secret(question string) (string, error) {
	fmt.Fprintf(t.f, "%s (hidden): ", question)
	b, err := term.ReadPassword(int(t.f.Fd()))
	fmt.Fprintln(t.f)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Script is a Prompter with prepared answers (tests). Out collects what was said and asked.
type Script struct {
	Answers []string
	Out     strings.Builder
}

func (s *Script) next() (string, error) {
	if len(s.Answers) == 0 {
		return "", errors.New("script: no answer left")
	}
	a := s.Answers[0]
	s.Answers = s.Answers[1:]
	return a, nil
}

func (s *Script) Say(format string, a ...any) { fmt.Fprintf(&s.Out, format, a...) }

func (s *Script) Ask(q, def string) (string, error) {
	fmt.Fprintf(&s.Out, "%s [%s]: ", q, def)
	a, err := s.next()
	if a == "" {
		a = def
	}
	fmt.Fprintln(&s.Out, a)
	return a, err
}

func (s *Script) YesNo(q string, def bool) (bool, error) {
	fmt.Fprintf(&s.Out, "%s ", q)
	a, err := s.next()
	fmt.Fprintln(&s.Out, a)
	switch strings.ToLower(a) {
	case "":
		return def, err
	case "y", "yes":
		return true, err
	}
	return false, err
}

func (s *Script) Secret(q string) (string, error) {
	fmt.Fprintf(&s.Out, "%s (hidden): ***\n", q) // a test transcript must not hold the value either
	return s.next()
}
