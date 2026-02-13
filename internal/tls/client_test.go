package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	timeout := 5 * time.Second
	client := NewClient(timeout)

	if client == nil {
		t.Fatal("expected non-nil client")
	}

	if client.timeout != timeout {
		t.Errorf("expected timeout %v, got %v", timeout, client.timeout)
	}
}

func TestClient_Fetch_Success(t *testing.T) {
	client := NewClient(10 * time.Second)
	ctx := context.Background()

	resp, err := client.Fetch(ctx, "example.com", "443")
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if resp.Host != "example.com" {
		t.Errorf("expected host 'example.com', got %s", resp.Host)
	}

	if resp.Port != "443" {
		t.Errorf("expected port '443', got %s", resp.Port)
	}

	if resp.TLSVersion == "" {
		t.Error("expected non-empty TLS version")
	}

	if !strings.HasPrefix(resp.TLSVersion, "TLS") {
		t.Errorf("expected TLS version to start with 'TLS', got %s", resp.TLSVersion)
	}

	if resp.CipherSuite == "" {
		t.Error("expected non-empty cipher suite")
	}

	if len(resp.Certificates) == 0 {
		t.Error("expected at least one certificate")
	}

	cert := resp.Certificates[0]
	if cert.Subject.CommonName == "" {
		t.Error("expected certificate to have common name")
	}

	if cert.NotBefore.IsZero() {
		t.Error("expected certificate to have NotBefore date")
	}

	if cert.NotAfter.IsZero() {
		t.Error("expected certificate to have NotAfter date")
	}

	if cert.SerialNumber == "" {
		t.Error("expected certificate to have serial number")
	}
}

func TestClient_Fetch_InvalidHost(t *testing.T) {
	client := NewClient(5 * time.Second)
	ctx := context.Background()

	_, err := client.Fetch(ctx, "invalid-host-that-does-not-exist.local", "443")
	if err == nil {
		t.Error("expected error for invalid host")
	}
}

func TestClient_Fetch_Timeout(t *testing.T) {
	client := NewClient(1 * time.Millisecond)
	ctx := context.Background()

	_, err := client.Fetch(ctx, "example.com", "443")
	if err == nil {
		t.Error("expected timeout error")
	}

	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline") {
		t.Errorf("expected timeout/deadline error, got: %v", err)
	}
}

func TestParseCertificate(t *testing.T) {
	client := NewClient(5 * time.Second)

	testCert := &x509.Certificate{
		SerialNumber: nil,
		Subject: pkix.Name{
			CommonName:         "example.com",
			Organization:       []string{"Example Org"},
			OrganizationalUnit: []string{"IT"},
			Country:            []string{"US"},
			Province:           []string{"CA"},
			Locality:           []string{"San Francisco"},
		},
		Issuer: pkix.Name{
			CommonName:   "Example CA",
			Organization: []string{"Example CA Org"},
		},
		NotBefore:          time.Now().Add(-24 * time.Hour),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		DNSNames:           []string{"example.com", "www.example.com"},
		IsCA:               false,
	}

	cert := client.parseCertificate(testCert)

	if cert.Subject.CommonName != "example.com" {
		t.Errorf("expected CN 'example.com', got %s", cert.Subject.CommonName)
	}

	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "Example Org" {
		t.Errorf("expected organization 'Example Org', got %v", cert.Subject.Organization)
	}

	if cert.Issuer.CommonName != "Example CA" {
		t.Errorf("expected issuer CN 'Example CA', got %s", cert.Issuer.CommonName)
	}

	if len(cert.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names, got %d", len(cert.DNSNames))
	}
}

func TestClient_Fetch_WithPort(t *testing.T) {
	client := NewClient(10 * time.Second)
	ctx := context.Background()

	resp, err := client.Fetch(ctx, "example.com", "443")
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if resp.Port != "443" {
		t.Errorf("expected port '443', got %s", resp.Port)
	}
}

func TestDialContext(t *testing.T) {
	client := NewClient(5 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := net.DialTimeout("tcp", "example.com:443", client.timeout)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
	})

	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Error("expected peer certificates")
	}
}
