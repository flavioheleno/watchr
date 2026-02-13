package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
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

var cipherSuitesByVersion = map[string][]uint16{
	"TLS 1.0": {
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	},
	"TLS 1.1": {
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	},
	"TLS 1.2": {
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	},
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
	}

	var anySupported bool
	for _, info := range tlsVersions {
		supported, err := s.testVersion(ctx, host, port, info.value)
		if err != nil {
			return nil, err
		}
		result.SupportedVersions[info.name] = supported
		if supported {
			anySupported = true
		}
	}

	result.PreferredVersion = highestSupported(result.SupportedVersions)

	if !anySupported {
		return result, nil
	}

	return result, nil
}

func (s *Scanner) EnumerateCiphers(ctx context.Context, host, port, version string) ([]string, error) {
	value, ok := tlsVersionLookup[version]
	if !ok {
		return nil, fmt.Errorf("unsupported TLS version %s", version)
	}

	if value == tls.VersionTLS13 {
		return s.enumerateTLS13(ctx, host, port)
	}

	suites := cipherSuitesByVersion[version]
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
		if info.value == tls.VersionTLS13 && !includeTLS13 {
			continue
		}

		ciphers, err := s.EnumerateCiphers(ctx, host, port, info.name)
		if err != nil {
			return nil, err
		}

		result.CipherSuites[info.name] = ciphers
	}

	result.PreferredVersion = highestSupported(result.SupportedVersions)
	if suites := result.CipherSuites[result.PreferredVersion]; len(suites) > 0 {
		result.PreferredCipher = suites[0]
	}

	s.DetectVulnerabilities(result)

	return result, nil
}

func (s *Scanner) enumerateTLS13(ctx context.Context, host, port string) ([]string, error) {
	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}

	conn, fatal, err := s.tryHandshake(ctx, host, port, cfg)
	if err != nil {
		if fatal {
			return nil, err
		}
		return nil, fmt.Errorf("TLS 1.3 not supported")
	}
	defer func() {
		_ = conn.Close()
	}()

	state := conn.ConnectionState()
	if state.CipherSuite == 0 {
		return nil, fmt.Errorf("unable to determine TLS 1.3 cipher suite")
	}

	return []string{tls.CipherSuiteName(state.CipherSuite)}, nil
}

func (s *Scanner) testVersion(ctx context.Context, host, port string, version uint16) (bool, error) {
	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         version,
		MaxVersion:         version,
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
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, true, err
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
