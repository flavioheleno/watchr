package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestDomainCommand_Execute(t *testing.T) {
	cmd := NewDomainCommand()

	if !strings.HasPrefix(cmd.Use, "domain") {
		t.Errorf("expected Use to start with 'domain', got %s", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("expected non-empty Short description")
	}

	if cmd.RunE == nil {
		t.Error("expected RunE to be set")
	}
}

func TestDomainCommand_RequiresArgument(t *testing.T) {
	cmd := NewDomainCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when no domain argument provided")
	}
}

func TestDomainCommand_WithValidDomain(t *testing.T) {
	cmd := NewDomainCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{"example.com"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Error("expected non-empty output")
	}

	if !strings.Contains(strings.ToLower(output), "source") {
		t.Error("expected output to contain 'source' field")
	}
}
