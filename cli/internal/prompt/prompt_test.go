package prompt

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
)

func terminal(input string) (*Terminal, *bytes.Buffer) {
	var out bytes.Buffer
	return &Terminal{In: bufio.NewReader(strings.NewReader(input)), Out: &out, FD: -1}, &out
}

func TestTerminalTextUsesDefaultAndRetriesInvalidAnswers(t *testing.T) {
	term, out := terminal("\nbad\ngood\n")
	got, err := term.Text("id", "Name", "", func(v string) error {
		if v != "good" {
			return errors.New("not good")
		}
		return nil
	})
	if err != nil || got != "good" {
		t.Fatalf("got %q, %v", got, err)
	}
	if !strings.Contains(out.String(), "An answer is required") || !strings.Contains(out.String(), "not good") {
		t.Fatalf("missing guidance: %s", out.String())
	}
	term, _ = terminal("\n")
	if got, _ := term.Text("id", "Name", "home", nil); got != "home" {
		t.Fatalf("default not used: %q", got)
	}
}

func TestTerminalChoices(t *testing.T) {
	term, _ := terminal("9\n2\n")
	if got, err := term.Choose("id", "Pick", []string{"a", "b"}, "a"); err != nil || got != "b" {
		t.Fatalf("Choose = %q, %v", got, err)
	}
	term, _ = terminal("3,1,1\n")
	got, err := term.ChooseMany("id", "Pick", []string{"a", "b", "c"}, nil)
	if err != nil || strings.Join(got, ",") != "a,c" {
		t.Fatalf("ChooseMany = %v, %v", got, err)
	}
	term, _ = terminal("maybe\nYES\n")
	if ok, err := term.Confirm("id", "Go", false); err != nil || !ok {
		t.Fatalf("Confirm = %v, %v", ok, err)
	}
}

func TestTerminalEndOfInputStops(t *testing.T) {
	term, _ := terminal("")
	if _, err := term.Text("id", "Name", "", nil); !errors.Is(err, ErrAborted) {
		t.Fatalf("expected ErrAborted, got %v", err)
	}
}

func TestTerminalSecretWithoutTerminalReadsLine(t *testing.T) {
	term, out := terminal("s3cret\n")
	got, err := term.Secret("id", "Secret", nil)
	if err != nil || got != "s3cret" {
		t.Fatalf("got %q, %v", got, err)
	}
	if strings.Contains(out.String(), "s3cret") {
		t.Fatal("secret echoed by the prompt")
	}
}

func TestScriptedRequiresDecisions(t *testing.T) {
	s := &Scripted{Answers: map[string]string{"pick": "b", "many": "c,a", "yes": "no"}}
	if _, err := s.Text("missing", "Name", "", nil); err == nil {
		t.Fatal("missing answer without default must fail")
	}
	if got, _ := s.Text("missing", "Name", "def", nil); got != "def" {
		t.Fatalf("default not used: %q", got)
	}
	if got, err := s.Choose("pick", "Pick", []string{"a", "b"}, "a"); err != nil || got != "b" {
		t.Fatalf("Choose = %q, %v", got, err)
	}
	if _, err := s.Choose("pick", "Pick", []string{"x"}, ""); err == nil {
		t.Fatal("answer outside the options must fail")
	}
	if got, err := s.ChooseMany("many", "Pick", []string{"a", "b", "c"}, nil); err != nil || strings.Join(got, ",") != "a,c" {
		t.Fatalf("ChooseMany = %v, %v", got, err)
	}
	if ok, _ := s.Confirm("yes", "Go", true); ok {
		t.Fatal("scripted no ignored")
	}
	if _, err := s.Secret("missing", "Secret", nil); err == nil {
		t.Fatal("secrets never default")
	}
}
