package tls

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewScanner(t *testing.T) {
	timeout := 5 * time.Second
	scanner := NewScanner(timeout)

	if scanner == nil {
		t.Fatal("expected non-nil scanner")
	}

	if scanner.timeout != timeout {
		t.Errorf("expected timeout %v, got %v", timeout, scanner.timeout)
	}
}

func TestScanner_TestVersions_Success(t *testing.T) {
	scanner := NewScanner(10 * time.Second)
	ctx := context.Background()

	result, err := scanner.TestVersions(ctx, "example.com", "443")
	if err != nil {
		t.Fatalf("TestVersions failed: %v", err)
	}

	if result.Host != "example.com" {
		t.Errorf("expected host 'example.com', got %s", result.Host)
	}

	if result.Port != "443" {
		t.Errorf("expected port '443', got %s", result.Port)
	}

	if len(result.SupportedVersions) == 0 {
		t.Error("expected version test results")
	}

	// Verify that at least one modern TLS version is supported
	// Note: We don't assert specific version support for external servers
	// as their TLS configuration may change over time
	if !result.SupportedVersions["TLS 1.2"] && !result.SupportedVersions["TLS 1.3"] {
		t.Error("example.com should support at least TLS 1.2 or 1.3")
	}
}

func TestScanner_TestVersions_InvalidHost(t *testing.T) {
	scanner := NewScanner(5 * time.Second)
	ctx := context.Background()

	_, err := scanner.TestVersions(ctx, "invalid-host-does-not-exist.local", "443")
	if err == nil {
		t.Error("expected error for invalid host")
	}
}

func TestScanner_TestVersions_Timeout(t *testing.T) {
	scanner := NewScanner(1 * time.Millisecond)
	ctx := context.Background()

	_, err := scanner.TestVersions(ctx, "example.com", "443")
	if err == nil {
		t.Error("expected timeout error")
	}

	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline") {
		t.Logf("got error: %v (expected timeout/deadline)", err)
	}
}

func TestScanner_EnumerateCiphers_TLS12(t *testing.T) {
	scanner := NewScanner(10 * time.Second)
	ctx := context.Background()

	ciphers, err := scanner.EnumerateCiphers(ctx, "example.com", "443", "TLS 1.2")
	if err != nil {
		t.Fatalf("EnumerateCiphers failed: %v", err)
	}

	if len(ciphers) == 0 {
		t.Error("expected at least one supported cipher suite for TLS 1.2")
	}

	for _, cipher := range ciphers {
		if cipher == "" {
			t.Error("expected non-empty cipher suite name")
		}
		if !strings.Contains(cipher, "TLS_") {
			t.Errorf("expected cipher name to start with TLS_, got %s", cipher)
		}
	}
}

func TestScanner_EnumerateCiphers_InvalidVersion(t *testing.T) {
	scanner := NewScanner(5 * time.Second)
	ctx := context.Background()

	_, err := scanner.EnumerateCiphers(ctx, "example.com", "443", "TLS 9.9")
	if err == nil {
		t.Error("expected error for invalid TLS version")
	}
}

func TestScanner_DetectVulnerabilities(t *testing.T) {
	result := &TestResult{
		Host: "example.com",
		Port: "443",
		SupportedVersions: map[string]bool{
			"TLS 1.0": false,
			"TLS 1.1": false,
			"TLS 1.2": true,
			"TLS 1.3": true,
		},
		CipherSuites: map[string][]string{
			"TLS 1.2": {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		},
	}

	scanner := NewScanner(5 * time.Second)
	scanner.DetectVulnerabilities(result)

	if len(result.Vulnerabilities) > 0 {
		for _, vuln := range result.Vulnerabilities {
			if strings.Contains(vuln, "TLS 1.0") || strings.Contains(vuln, "TLS 1.1") {
				t.Errorf("should not report TLS 1.0/1.1 as vulnerability when not supported")
			}
		}
	}
}

func TestScanner_DetectVulnerabilities_WeakTLS(t *testing.T) {
	result := &TestResult{
		Host: "test.com",
		Port: "443",
		SupportedVersions: map[string]bool{
			"TLS 1.0": true,
			"TLS 1.1": true,
			"TLS 1.2": true,
			"TLS 1.3": false,
		},
	}

	scanner := NewScanner(5 * time.Second)
	scanner.DetectVulnerabilities(result)

	hasWarning := false
	for _, vuln := range result.Vulnerabilities {
		if strings.Contains(vuln, "TLS 1.0") || strings.Contains(vuln, "TLS 1.1") {
			hasWarning = true
			break
		}
	}

	if !hasWarning {
		t.Error("expected vulnerability warning for TLS 1.0/1.1 support")
	}
}

func TestScanner_FullTest(t *testing.T) {
	scanner := NewScanner(30 * time.Second)
	ctx := context.Background()

	result, err := scanner.FullTest(ctx, "example.com", "443", false)
	if err != nil {
		t.Fatalf("FullTest failed: %v", err)
	}

	if result.Host != "example.com" {
		t.Errorf("expected host 'example.com', got %s", result.Host)
	}

	if len(result.SupportedVersions) == 0 {
		t.Error("expected version test results")
	}

	if result.PreferredVersion == "" {
		t.Error("expected preferred version to be set")
	}
}
