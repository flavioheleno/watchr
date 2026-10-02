package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"
)

type Scanner struct {
	timeout time.Duration
}

type versionInfo struct {
	name  string
	value uint16
}

var tlsVersions = []versionInfo{
	{name: "TLS 1.0", value: tls.VersionTLS10},
	{name: "TLS 1.1", value: tls.VersionTLS11},
	{name: "TLS 1.2", value: tls.VersionTLS12},
	{name: "TLS 1.3", value: tls.VersionTLS13},
}

var tlsVersionLookup = map[string]uint16{
	"TLS 1.0": tls.VersionTLS10,
	"TLS 1.1": tls.VersionTLS11,
	"TLS 1.2": tls.VersionTLS12,
	"TLS 1.3": tls.VersionTLS13,
}

var preferredVersionOrder = []string{"TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"}

func cipherSuitesForVersion(version uint16) []uint16 {
	var suites []uint16
	for _, suite := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		if version != tls.VersionTLS13 && slices.Contains(suite.SupportedVersions, version) {
			suites = append(suites, suite.ID)
		}
	}
	return suites
}

func NewScanner(timeout time.Duration) *Scanner {
	return &Scanner{timeout: timeout}
}

func (s *Scanner) TestVersions(ctx context.Context, host, port string) (*TestResult, error) {
	if host == "" {
		return nil, fmt.Errorf("host is required")
	}
	if port == "" {
		port = "443"
	}

	result := &TestResult{
		Host:              host,
		Port:              port,
		SupportedVersions: make(map[string]bool, len(tlsVersions)),
		ScanLimitations:   []string{"Protocol and cipher probes are limited to Go crypto/tls capabilities; other suites may be supported by the server."},
	}

	for _, info := range tlsVersions {
		supported, err := s.testVersion(ctx, host, port, info.value)
		if err != nil {
			return nil, err
		}
		result.SupportedVersions[info.name] = supported
	}

	result.PreferredVersion = highestSupported(result.SupportedVersions)

	return result, nil
}

func (s *Scanner) EnumerateCiphers(ctx context.Context, host, port, version string) ([]string, error) {
	value, ok := tlsVersionLookup[version]
	if !ok {
		return nil, fmt.Errorf("unsupported TLS version %s", version)
	}

	if value == tls.VersionTLS13 {
		return nil, fmt.Errorf("TLS 1.3 cipher enumeration is unavailable in Go crypto/tls")
	}

	suites := cipherSuitesForVersion(value)
	if len(suites) == 0 {
		return nil, fmt.Errorf("no cipher suites configured for %s", version)
	}

	supported := make([]string, 0, len(suites))
	for _, suite := range suites {
		cfg := &tls.Config{
			ServerName:         host,
			MinVersion:         value,
			MaxVersion:         value,
			CipherSuites:       []uint16{suite},
			InsecureSkipVerify: true,
		}

		conn, fatal, err := s.tryHandshake(ctx, host, port, cfg)
		if err != nil {
			if fatal {
				return nil, err
			}
			continue
		}

		if err := conn.Close(); err != nil {
			return nil, err
		}
		supported = append(supported, tls.CipherSuiteName(suite))
	}

	if len(supported) == 0 {
		return nil, fmt.Errorf("no cipher suites detected for %s", version)
	}

	return supported, nil
}

func (s *Scanner) DetectVulnerabilities(result *TestResult) {
	if result == nil {
		return
	}

	addWarning := func(message string) {
		for _, existing := range result.Vulnerabilities {
			if existing == message {
				return
			}
		}
		result.Vulnerabilities = append(result.Vulnerabilities, message)
	}

	if result.SupportedVersions["TLS 1.0"] {
		addWarning("Server supports deprecated TLS 1.0")
	}
	if result.SupportedVersions["TLS 1.1"] {
		addWarning("Server supports deprecated TLS 1.1")
	}
	if !result.SupportedVersions["TLS 1.2"] && !result.SupportedVersions["TLS 1.3"] {
		addWarning("Server does not support modern TLS (1.2+)")
	}
}

func (s *Scanner) FullTest(ctx context.Context, host, port string, includeTLS13 bool) (*TestResult, error) {
	result, err := s.TestVersions(ctx, host, port)
	if err != nil {
		return nil, err
	}

	result.CipherSuites = make(map[string][]string)

	for _, info := range tlsVersions {
		if !result.SupportedVersions[info.name] {
			continue
		}
		if info.value == tls.VersionTLS13 {
			if includeTLS13 {
				cipher, err := s.negotiatedCipher(ctx, host, result.Port, info.value)
				if err != nil {
					return nil, err
				}
				result.NegotiatedTLS13Cipher = cipher
				result.ScanLimitations = append(result.ScanLimitations, "TLS 1.3 shows one negotiated cipher; its cipher suites cannot be enumerated by Go crypto/tls.")
			}
			continue
		}

		ciphers, err := s.EnumerateCiphers(ctx, host, result.Port, info.name)
		if err != nil {
			return nil, err
		}

		result.CipherSuites[info.name] = ciphers
	}

	result.PreferredVersion = highestSupported(result.SupportedVersions)
	if result.NegotiatedTLS13Cipher != "" {
		result.PreferredCipher = result.NegotiatedTLS13Cipher
	} else if result.PreferredVersion != "" && result.PreferredVersion != "TLS 1.3" {
		cipher, err := s.negotiatedCipher(ctx, host, result.Port, tlsVersionLookup[result.PreferredVersion])
		if err != nil {
			return nil, err
		}
		result.PreferredCipher = cipher
	}

	s.DetectVulnerabilities(result)

	return result, nil
}

func (s *Scanner) negotiatedCipher(ctx context.Context, host, port string, version uint16) (string, error) {
	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         version,
		MaxVersion:         version,
		CipherSuites:       cipherSuitesForVersion(version),
		InsecureSkipVerify: true,
	}

	conn, fatal, err := s.tryHandshake(ctx, host, port, cfg)
	if err != nil {
		if fatal {
			return "", err
		}
		return "", err
	}
	defer func() {
		_ = conn.Close()
	}()

	state := conn.ConnectionState()
	if state.CipherSuite == 0 {
		return "", fmt.Errorf("unable to determine negotiated cipher suite")
	}

	return tls.CipherSuiteName(state.CipherSuite), nil
}

func (s *Scanner) testVersion(ctx context.Context, host, port string, version uint16) (bool, error) {
	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         version,
		MaxVersion:         version,
		CipherSuites:       cipherSuitesForVersion(version),
		InsecureSkipVerify: true,
	}

	conn, fatal, err := s.tryHandshake(ctx, host, port, cfg)
	if err != nil {
		if fatal {
			return false, err
		}
		return false, nil
	}
	if err := conn.Close(); err != nil {
		return false, err
	}

	return true, nil
}

func (s *Scanner) tryHandshake(ctx context.Context, host, port string, cfg *tls.Config) (*tls.Conn, bool, error) {
	ctxWithTimeout, cancel := s.withTimeout(ctx)
	defer cancel()

	dialer := &net.Dialer{}
	if s.timeout > 0 {
		dialer.Timeout = s.timeout
	}

	conn, err := dialer.DialContext(ctxWithTimeout, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, true, err
	}

	client := tls.Client(conn, cfg)
	if err := client.HandshakeContext(ctxWithTimeout); err != nil {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		if ctxWithTimeout.Err() != nil {
			return nil, true, ctxWithTimeout.Err()
		}
		return nil, false, err
	}

	return client, false, nil
}

func (s *Scanner) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.timeout <= 0 {
		// Return a proper cancel function even when no timeout is set
		// to ensure context resources are properly cleaned up
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, s.timeout)
}

func highestSupported(supported map[string]bool) string {
	for _, version := range preferredVersionOrder {
		if supported[version] {
			return version
		}
	}
	return ""
}
