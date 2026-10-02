package tls

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestScannerVersionAndCipherCoverage(t *testing.T) {
	for _, tt := range []struct {
		name    string
		version uint16
		cipher  uint16
	}{
		{"TLS 1.0", tls.VersionTLS10, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
		{"TLS 1.1", tls.VersionTLS11, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
		{"TLS 1.2", tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
		{"TLS 1.2", tls.VersionTLS12, tls.TLS_RSA_WITH_AES_128_CBC_SHA},
		{"TLS 1.2", tls.VersionTLS12, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
	} {
		t.Run(tt.name+"/"+tls.CipherSuiteName(tt.cipher), func(t *testing.T) {
			host, port := startTLSServer(t, &tls.Config{
				MinVersion: tt.version, MaxVersion: tt.version, CipherSuites: []uint16{tt.cipher},
			})
			scanner := NewScanner(time.Second)
			result, err := scanner.FullTest(context.Background(), host, port, true)
			if err != nil {
				t.Fatal(err)
			}
			for _, info := range tlsVersions {
				if result.SupportedVersions[info.name] != (info.value == tt.version) {
					t.Fatalf("incorrect versions: %v", result.SupportedVersions)
				}
			}
			cipher := tls.CipherSuiteName(tt.cipher)
			if !slices.Equal(result.CipherSuites[tt.name], []string{cipher}) {
				t.Fatalf("unexpected suites: %v", result.CipherSuites)
			}
			if result.PreferredCipher != cipher {
				t.Fatalf("incorrect negotiated cipher: %s", result.PreferredCipher)
			}
		})
	}
}

func TestScannerTLS13ReportsNegotiatedCipher(t *testing.T) {
	host, port := startTLSServer(t, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	scanner := NewScanner(time.Second)
	result, err := scanner.FullTest(context.Background(), host, port, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.CipherSuites["TLS 1.3"]) != 0 {
		t.Fatalf("negotiated cipher mislabeled as enumeration: %v", result.CipherSuites)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["negotiatedTLS13Cipher"] == nil || fields["scanLimitations"] == nil {
		t.Fatalf("missing negotiation/coverage metadata: %s", data)
	}
	if _, err := scanner.EnumerateCiphers(context.Background(), host, port, "TLS 1.3"); err == nil {
		t.Fatal("TLS 1.3 enumeration should explicitly report its limitation")
	}
}

func TestScannerErrors(t *testing.T) {
	scanner := NewScanner(time.Second)
	if _, err := scanner.TestVersions(context.Background(), "", "443"); err == nil {
		t.Fatal("expected missing host error")
	}
	if _, err := scanner.EnumerateCiphers(context.Background(), "127.0.0.1", "443", "TLS 9.9"); err == nil {
		t.Fatal("expected version error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanner.TestVersions(ctx, "127.0.0.1", "443"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	host, port := startStalledServer(t)
	if _, err := NewScanner(20*time.Millisecond).TestVersions(context.Background(), host, port); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", err)
	}
}

func TestScannerDetectVulnerabilities(t *testing.T) {
	for _, tt := range []struct {
		name     string
		versions map[string]bool
		want     int
	}{
		{"modern", map[string]bool{"TLS 1.2": true, "TLS 1.3": true}, 0},
		{"legacy", map[string]bool{"TLS 1.0": true, "TLS 1.1": true}, 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := &TestResult{SupportedVersions: tt.versions}
			scanner := NewScanner(time.Second)
			scanner.DetectVulnerabilities(result)
			scanner.DetectVulnerabilities(result)
			if len(result.Vulnerabilities) != tt.want {
				t.Fatalf("warnings: %v", result.Vulnerabilities)
			}
			for _, warning := range result.Vulnerabilities {
				if !strings.Contains(warning, "TLS") {
					t.Fatalf("unexpected warning: %s", warning)
				}
			}
		})
	}
}
