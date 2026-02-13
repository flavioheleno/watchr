package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"time"
)

type Client struct {
	timeout time.Duration
}

func NewClient(timeout time.Duration) *Client {
	return &Client{
		timeout: timeout,
	}
}

func (c *Client) Fetch(ctx context.Context, host, port string) (*Response, error) {
	address := net.JoinHostPort(host, port)

	slog.Debug("connecting to TLS server", "address", address)

	dialer := &net.Dialer{
		Timeout: c.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.Close()
	}()

	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}

	tlsConn := tls.Client(conn, tlsConfig)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	defer func() {
		_ = tlsConn.Close()
	}()

	state := tlsConn.ConnectionState()

	response := &Response{
		Host:         host,
		Port:         port,
		TLSVersion:   tlsVersionString(state.Version),
		CipherSuite:  tls.CipherSuiteName(state.CipherSuite),
		Certificates: make([]Certificate, 0),
	}

	for _, cert := range state.PeerCertificates {
		response.Certificates = append(response.Certificates, c.parseCertificate(cert))
	}

	if len(state.VerifiedChains) > 0 {
		response.VerifiedChains = make([][]int, len(state.VerifiedChains))
		for i, chain := range state.VerifiedChains {
			response.VerifiedChains[i] = make([]int, len(chain))
			for j := range chain {
				response.VerifiedChains[i][j] = j
			}
		}
	}

	return response, nil
}

func (c *Client) parseCertificate(cert *x509.Certificate) Certificate {
	parsed := Certificate{
		Subject:            parseSubject(cert.Subject),
		Issuer:             parseSubject(cert.Issuer),
		SerialNumber:       serialNumberToString(cert.SerialNumber),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		DNSNames:           cert.DNSNames,
		IsCA:               cert.IsCA,
	}

	// Extract public key size for different key types
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		parsed.PublicKeySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		parsed.PublicKeySize = pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		parsed.PublicKeySize = 256 // Ed25519 keys are always 256 bits
	}

	// Check certificate validity
	now := time.Now()
	if now.Before(cert.NotBefore) {
		slog.Warn("certificate is not yet valid", "subject", cert.Subject.CommonName, "notBefore", cert.NotBefore)
	} else if now.After(cert.NotAfter) {
		slog.Warn("certificate has expired", "subject", cert.Subject.CommonName, "notAfter", cert.NotAfter)
	} else if now.Add(30 * 24 * time.Hour).After(cert.NotAfter) {
		daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
		slog.Warn("certificate expiring soon", "subject", cert.Subject.CommonName, "notAfter", cert.NotAfter, "daysRemaining", daysUntilExpiry)
	}

	return parsed
}

func parseSubject(name interface{}) Subject {
	switch n := name.(type) {
	case pkix.Name:
		return Subject{
			CommonName:         n.CommonName,
			Organization:       n.Organization,
			OrganizationalUnit: n.OrganizationalUnit,
			Country:            n.Country,
			Province:           n.Province,
			Locality:           n.Locality,
		}
	default:
		return Subject{}
	}
}

func serialNumberToString(sn *big.Int) string {
	if sn == nil {
		return ""
	}
	return fmt.Sprintf("%X", sn)
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04X)", version)
	}
}
