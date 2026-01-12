package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestHTTPCommand_Execute(t *testing.T) {
	cmd := NewHTTPCommand()

	if !strings.HasPrefix(cmd.Use, "http") {
		t.Errorf("expected Use to start with 'http', got %s", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("expected non-empty Short description")
	}

	if cmd.RunE == nil {
		t.Error("expected RunE to be set")
	}
}

func TestHTTPCommand_RequiresArgument(t *testing.T) {
	cmd := NewHTTPCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when no URL argument provided")
	}
}

func TestHTTPCommand_WithValidURL(t *testing.T) {
	cmd := NewHTTPCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{"https://example.com"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Error("expected non-empty output")
	}

	if !strings.Contains(output, "example.com") {
		t.Error("expected output to contain URL")
	}

	if !strings.Contains(output, "Status") {
		t.Error("expected output to contain status")
	}
}
