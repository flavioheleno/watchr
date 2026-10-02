package tls

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"testing"
	"time"
)

func TestClientFetch(t *testing.T) {
	host, port := startTLSServer(t, nil)
	resp, err := NewClient(time.Second).Fetch(context.Background(), host, port)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Host != host || resp.Port != port || resp.TLSVersion == "" || resp.CipherSuite == "" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if len(resp.Certificates) == 0 {
		t.Fatal("missing certificates")
	}
	cert := resp.Certificates[0]
	if cert.NotBefore.IsZero() || cert.NotAfter.IsZero() || cert.SerialNumber == "" || cert.PublicKeySize == 0 {
		t.Fatalf("missing certificate details: %+v", cert)
	}
}

func TestClientFetchHandshakeDeadline(t *testing.T) {
	for _, tt := range []struct {
		name          string
		timeout       time.Duration
		parentTimeout time.Duration
		parentExpires bool
	}{
		{"client timeout", 20 * time.Millisecond, time.Second, false},
		{"parent deadline", time.Second, 20 * time.Millisecond, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			host, port := startStalledServer(t)
			ctx, cancel := context.WithTimeout(context.Background(), tt.parentTimeout)
			defer cancel()
			_, err := NewClient(tt.timeout).Fetch(ctx, host, port)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected deadline error, got %v", err)
			}
			if (ctx.Err() != nil) != tt.parentExpires {
				t.Fatalf("client timeout did not bound the handshake: parent error=%v", ctx.Err())
			}
		})
	}
}

func TestClientFetchCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewClient(time.Second).Fetch(ctx, "127.0.0.1", "443")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestClientFetchConnectionError(t *testing.T) {
	_, err := NewClient(time.Second).Fetch(context.Background(), "127.0.0.1", "invalid-port")
	if err == nil {
		t.Fatal("expected connection error")
	}
}

func TestParseCertificate(t *testing.T) {
	testCert := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "example.com", Organization: []string{"Example Org"}},
		Issuer:             pkix.Name{CommonName: "Example CA"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		DNSNames:           []string{"example.com", "www.example.com"},
	}
	cert := NewClient(time.Second).parseCertificate(testCert)
	if cert.Subject.CommonName != "example.com" || cert.Issuer.CommonName != "Example CA" || len(cert.DNSNames) != 2 || cert.SerialNumber != "" {
		t.Fatalf("unexpected parsed certificate: %+v", cert)
	}
}

func startStalledServer(t *testing.T) (string, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		<-release
	}()
	t.Cleanup(func() {
		close(release)
		_ = listener.Close()
		<-done
	})
	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
