// Package prompt asks the setup questions. Every question has a stable ID so
// a scripted run (tests, or an answers file) can supply the same answers.
package prompt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// Asker is implemented by the terminal and by scripted answers.
type Asker interface {
	// Text returns a line of text. An empty reply selects def.
	Text(id, label, def string, check func(string) error) (string, error)
	// Choose returns one of options. An empty reply selects def.
	Choose(id, label string, options []string, def string) (string, error)
	// ChooseMany returns a non-empty subset of options, in option order.
	ChooseMany(id, label string, options []string, defs []string) ([]string, error)
	// Confirm returns yes or no. An empty reply selects def.
	Confirm(id, label string, def bool) (bool, error)
	// Secret returns a value typed without echo. It is never printed.
	Secret(id, label string, check func(string) error) (string, error)
	// Say prints guidance.
	Say(format string, args ...any)
}

// ErrAborted reports that the person stopped the setup.
var ErrAborted = errors.New("stopped at your request")

// Terminal asks on a terminal. Invalid answers are explained and asked again.
type Terminal struct {
	In  *bufio.Reader
	Out io.Writer
	// FD is the input file descriptor used to hide secrets.
	FD int
}

// NewTerminal uses standard input and output.
func NewTerminal() *Terminal {
	return &Terminal{In: bufio.NewReader(os.Stdin), Out: os.Stdout, FD: int(os.Stdin.Fd())}
}

func (t *Terminal) line() (string, error) {
	s, err := t.In.ReadString('\n')
	if err != nil && (s == "" || !errors.Is(err, io.EOF)) {
		if errors.Is(err, io.EOF) {
			return "", ErrAborted
		}
		return "", err
	}
	return strings.TrimSpace(s), nil
}

func (t *Terminal) Say(format string, args ...any) {
	fmt.Fprintf(t.Out, format+"\n", args...)
}

func (t *Terminal) Text(id, label, def string, check func(string) error) (string, error) {
	for {
		if def != "" {
			fmt.Fprintf(t.Out, "? %s [%s]: ", label, def)
		} else {
			fmt.Fprintf(t.Out, "? %s: ", label)
		}
		s, err := t.line()
		if err != nil {
			return "", err
		}
		if s == "" {
			s = def
		}
		if s == "" {
			fmt.Fprintln(t.Out, "  An answer is required.")
			continue
		}
		if check != nil {
			if err := check(s); err != nil {
				fmt.Fprintf(t.Out, "  %v\n", err)
				continue
			}
		}
		return s, nil
	}
}

func (t *Terminal) Choose(id, label string, options []string, def string) (string, error) {
	for {
		fmt.Fprintf(t.Out, "? %s\n", label)
		for i, o := range options {
			mark := " "
			if o == def {
				mark = "*"
			}
			fmt.Fprintf(t.Out, "  %s %d) %s\n", mark, i+1, o)
		}
		fmt.Fprint(t.Out, "  Number: ")
		s, err := t.line()
		if err != nil {
			return "", err
		}
		if s == "" && def != "" {
			return def, nil
		}
		if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= len(options) {
			return options[n-1], nil
		}
		fmt.Fprintln(t.Out, "  Type one of the numbers shown.")
	}
}

func (t *Terminal) ChooseMany(id, label string, options []string, defs []string) ([]string, error) {
	for {
		fmt.Fprintf(t.Out, "? %s\n", label)
		for i, o := range options {
			mark := " "
			if contains(defs, o) {
				mark = "*"
			}
			fmt.Fprintf(t.Out, "  %s %d) %s\n", mark, i+1, o)
		}
		fmt.Fprint(t.Out, "  Numbers separated by commas: ")
		s, err := t.line()
		if err != nil {
			return nil, err
		}
		if s == "" && len(defs) > 0 {
			return order(options, defs), nil
		}
		picked, ok := []string{}, true
		for _, part := range strings.Split(s, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil || n < 1 || n > len(options) {
				ok = false
				break
			}
			if !contains(picked, options[n-1]) {
				picked = append(picked, options[n-1])
			}
		}
		if ok && len(picked) > 0 {
			return order(options, picked), nil
		}
		fmt.Fprintln(t.Out, "  Type one or more of the numbers shown, for example 1,3.")
	}
}

func (t *Terminal) Confirm(id, label string, def bool) (bool, error) {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	for {
		fmt.Fprintf(t.Out, "? %s (%s): ", label, hint)
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
		fmt.Fprintln(t.Out, "  Answer yes or no.")
	}
}

func (t *Terminal) Secret(id, label string, check func(string) error) (string, error) {
	for {
		fmt.Fprintf(t.Out, "? %s (hidden): ", label)
		var s string
		if term.IsTerminal(t.FD) {
			b, err := term.ReadPassword(t.FD)
			fmt.Fprintln(t.Out)
			if err != nil {
				return "", err
			}
			s = strings.TrimSpace(string(b))
		} else {
			var err error
			if s, err = t.line(); err != nil {
				return "", err
			}
		}
		if s == "" {
			fmt.Fprintln(t.Out, "  A value is required.")
			continue
		}
		if check != nil {
			if err := check(s); err != nil {
				fmt.Fprintf(t.Out, "  %v\n", err)
				continue
			}
		}
		return s, nil
	}
}

// Scripted answers questions from a map keyed by question ID. A missing answer
// takes the default when there is one; otherwise the run stops, so a script
// never silently accepts something it did not decide.
type Scripted struct {
	Answers map[string]string
	Out     io.Writer
}

func (s *Scripted) Say(format string, args ...any) {
	if s.Out != nil {
		fmt.Fprintf(s.Out, format+"\n", args...)
	}
}

func (s *Scripted) answer(id string) (string, bool) {
	v, ok := s.Answers[id]
	return v, ok
}

func (s *Scripted) Text(id, label, def string, check func(string) error) (string, error) {
	v, ok := s.answer(id)
	if !ok || v == "" {
		v = def
	}
	if v == "" {
		return "", fmt.Errorf("no scripted answer for %q (%s)", id, label)
	}
	if check != nil {
		if err := check(v); err != nil {
			return "", fmt.Errorf("scripted answer for %q: %w", id, err)
		}
	}
	return v, nil
}

func (s *Scripted) Choose(id, label string, options []string, def string) (string, error) {
	v, ok := s.answer(id)
	if !ok || v == "" {
		v = def
	}
	if !contains(options, v) {
		return "", fmt.Errorf("scripted answer for %q must be one of %v", id, options)
	}
	return v, nil
}

func (s *Scripted) ChooseMany(id, label string, options []string, defs []string) ([]string, error) {
	v, ok := s.answer(id)
	if !ok || v == "" {
		if len(defs) == 0 {
			return nil, fmt.Errorf("no scripted answer for %q (%s)", id, label)
		}
		return order(options, defs), nil
	}
	var picked []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if !contains(options, part) {
			return nil, fmt.Errorf("scripted answer for %q: %q is not one of %v", id, part, options)
		}
		picked = append(picked, part)
	}
	return order(options, picked), nil
}

func (s *Scripted) Confirm(id, label string, def bool) (bool, error) {
	v, ok := s.answer(id)
	if !ok || v == "" {
		return def, nil
	}
	switch strings.ToLower(v) {
	case "y", "yes", "true":
		return true, nil
	case "n", "no", "false":
		return false, nil
	}
	return false, fmt.Errorf("scripted answer for %q must be yes or no", id)
}

func (s *Scripted) Secret(id, label string, check func(string) error) (string, error) {
	v, ok := s.answer(id)
	if !ok || v == "" {
		return "", fmt.Errorf("no scripted answer for %q (%s)", id, label)
	}
	if check != nil {
		if err := check(v); err != nil {
			return "", fmt.Errorf("scripted answer for %q: %w", id, err)
		}
	}
	return v, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func order(options, picked []string) []string {
	var out []string
	for _, o := range options {
		if contains(picked, o) {
			out = append(out, o)
		}
	}
	return out
}
