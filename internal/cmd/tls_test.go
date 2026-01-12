package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestTLSCommand_Execute(t *testing.T) {
	cmd := NewTLSCommand()

	if !strings.HasPrefix(cmd.Use, "tls") {
		t.Errorf("expected Use to start with 'tls', got %s", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("expected non-empty Short description")
	}

	if cmd.RunE == nil {
		t.Error("expected RunE to be set")
	}
}

func TestTLSCommand_RequiresArgument(t *testing.T) {
	cmd := NewTLSCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when no host argument provided")
	}
}

func TestTLSCommand_WithValidHost(t *testing.T) {
	cmd := NewTLSCommand()
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
		t.Error("expected output to contain host")
	}

	if !strings.Contains(output, "TLS") {
		t.Error("expected output to contain TLS")
	}
}

func TestTLSCommand_WithPort(t *testing.T) {
	cmd := NewTLSCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{"example.com", "--port", "443"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "example.com") {
		t.Error("expected output to contain host")
	}
}

func TestTLSCommand_WithScanProtocols(t *testing.T) {
	cmd := NewTLSCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{"example.com", "--scan-protocols"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Supported TLS Versions") {
		t.Error("expected output to contain 'Supported TLS Versions'")
	}

	if !strings.Contains(output, "TLS 1.2") || !strings.Contains(output, "TLS 1.3") {
		t.Error("expected output to contain TLS version information")
	}
}

func TestTLSCommand_WithScanCiphers(t *testing.T) {
	cmd := NewTLSCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{"example.com", "--scan-ciphers"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Supported TLS Versions") {
		t.Error("expected output to contain 'Supported TLS Versions'")
	}

	if !strings.Contains(output, "Supported Cipher Suites") {
		t.Error("expected output to contain 'Supported Cipher Suites'")
	}
}

func TestTLSCommand_WithFullScan(t *testing.T) {
	cmd := NewTLSCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{"example.com", "--full-scan"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Supported TLS Versions") {
		t.Error("expected output to contain 'Supported TLS Versions'")
	}

	if !strings.Contains(output, "Supported Cipher Suites") {
		t.Error("expected output to contain 'Supported Cipher Suites'")
	}

	if !strings.Contains(output, "Preferred Version") {
		t.Error("expected output to contain 'Preferred Version'")
	}
}
