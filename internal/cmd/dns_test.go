package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestDNSCommand_Execute(t *testing.T) {
	cmd := NewDNSCommand()

	if !strings.HasPrefix(cmd.Use, "dns") {
		t.Errorf("expected Use to start with 'dns', got %s", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("expected non-empty Short description")
	}

	if cmd.RunE == nil {
		t.Error("expected RunE to be set")
	}
}

func TestDNSCommand_RequiresArgument(t *testing.T) {
	cmd := NewDNSCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when no domain argument provided")
	}
}

func TestDNSCommand_WithValidDomain(t *testing.T) {
	cmd := NewDNSCommand()
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

	if !strings.Contains(output, "example.com") {
		t.Error("expected output to contain domain")
	}

	if !strings.Contains(output, "Records") {
		t.Error("expected output to contain records")
	}
}

func TestDNSCommand_WithRecordType(t *testing.T) {
	cmd := NewDNSCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{"example.com", "--type", "AAAA"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "AAAA") {
		t.Error("expected output to contain AAAA record type")
	}
}

func TestDNSCommand_WithCustomServer(t *testing.T) {
	cmd := NewDNSCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{"example.com", "--server", "1.1.1.1:53"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "1.1.1.1:53") {
		t.Error("expected output to contain custom nameserver")
	}
}
