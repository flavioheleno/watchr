package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	dnsinfo "watchr/internal/dns"
	httpinfo "watchr/internal/http"
	"watchr/internal/rdap"
	tlsinfo "watchr/internal/tls"
)

func TestNewFormatter(t *testing.T) {
	buf := new(bytes.Buffer)

	f := NewFormatter("json", buf)
	if f == nil {
		t.Fatal("expected non-nil formatter")
	}

	if f.format != "json" {
		t.Errorf("expected format 'json', got %s", f.format)
	}
}

func TestFormatter_OutputRDAP_Text(t *testing.T) {
	buf := new(bytes.Buffer)
	f := NewFormatter("text", buf)

	resp := &rdap.Response{
		LDHName: "example.com",
		Handle:  "TEST123",
		Status:  []string{"active"},
		Events: []rdap.Event{
			{
				EventAction: "registration",
				EventDate:   time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		Nameservers: []rdap.Nameserver{
			{LDHName: "ns1.example.com"},
		},
	}

	err := f.OutputRDAP(resp)
	if err != nil {
		t.Fatalf("OutputRDAP failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "example.com") {
		t.Error("expected output to contain domain name")
	}

	if !strings.Contains(output, "TEST123") {
		t.Error("expected output to contain handle")
	}

	if !strings.Contains(output, "active") {
		t.Error("expected output to contain status")
	}

	if !strings.Contains(output, "Source: RDAP") {
		t.Error("expected output to contain source")
	}
}

func TestFormatter_OutputRDAP_JSON(t *testing.T) {
	buf := new(bytes.Buffer)
	f := NewFormatter("json", buf)

	resp := &rdap.Response{
		LDHName: "example.com",
		Handle:  "TEST123",
		Status:  []string{"active"},
	}

	err := f.OutputRDAP(resp)
	if err != nil {
		t.Fatalf("OutputRDAP failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if result["ldhName"] != "example.com" {
		t.Error("expected ldhName in JSON output")
	}

	if result["handle"] != "TEST123" {
		t.Error("expected handle in JSON output")
	}
}

func TestFormatter_OutputWHOIS_Text(t *testing.T) {
	buf := new(bytes.Buffer)
	f := NewFormatter("text", buf)

	whoisData := sampleWHOISRecord()

	err := f.OutputWHOIS(whoisData)
	if err != nil {
		t.Fatalf("OutputWHOIS failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "Domain: example.com") {
		t.Error("expected output to contain parsed domain name")
	}

	if !strings.Contains(output, "Registrar: Example Registrar, Inc.") {
		t.Error("expected output to contain registrar line")
	}

	if !strings.Contains(output, "Status: clientTransferProhibited") {
		t.Error("expected output to contain domain status")
	}

	if !strings.Contains(strings.ToLower(output), "name servers: ns1.example.com, ns2.example.com") {
		t.Error("expected output to contain name servers")
	}

	if !strings.Contains(output, "Raw WHOIS:") {
		t.Error("expected text output to include raw data section")
	}
}

func TestFormatter_OutputWHOIS_JSON(t *testing.T) {
	buf := new(bytes.Buffer)
	f := NewFormatter("json", buf)

	whoisData := sampleWHOISRecord()

	err := f.OutputWHOIS(whoisData)
	if err != nil {
		t.Fatalf("OutputWHOIS failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if result["source"] != "WHOIS" {
		t.Error("expected source in JSON output")
	}

	if result["raw"] != whoisData {
		t.Error("expected raw field to contain the WHOIS data")
	}

	parsed, ok := result["parsed"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected parsed object in JSON output")
	}

	domain, ok := parsed["domain"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected domain object inside parsed output")
	}

	if domain["domain"] != "example.com" {
		t.Error("expected parsed domain to be example.com")
	}
}

func TestFormatter_OutputWHOIS_Text_FallbackOnParseError(t *testing.T) {
	buf := new(bytes.Buffer)
	f := NewFormatter("text", buf)

	whoisData := "INVALID WHOIS RESPONSE"

	err := f.OutputWHOIS(whoisData)
	if err != nil {
		t.Fatalf("OutputWHOIS failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, whoisData) {
		t.Error("expected fallback output to contain original WHOIS text")
	}

	if !strings.Contains(output, "Source: WHOIS") {
		t.Error("expected fallback output to contain source")
	}
}

func TestFormatter_OutputHTTP_Text(t *testing.T) {
	buf := new(bytes.Buffer)
	f := NewFormatter("text", buf)

	resp := &httpinfo.Response{
		URL:           "https://example.com",
		StatusCode:    200,
		Status:        "200 OK",
		ContentLength: 1234,
		Duration:      100 * time.Millisecond,
		Headers: map[string]string{
			"Content-Type": "text/html",
			"Server":       "nginx",
		},
		TLSVersion:     "TLS 1.3",
		TLSCipherSuite: "TLS_AES_128_GCM_SHA256",
	}

	err := f.OutputHTTP(resp)
	if err != nil {
		t.Fatalf("OutputHTTP failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "https://example.com") {
		t.Error("expected output to contain URL")
	}

	if !strings.Contains(output, "200 OK") {
		t.Error("expected output to contain status")
	}

	if !strings.Contains(output, "TLS 1.3") {
		t.Error("expected output to contain TLS version")
	}
}

func TestFormatter_OutputHTTP_JSON(t *testing.T) {
	buf := new(bytes.Buffer)
	f := NewFormatter("json", buf)

	resp := &httpinfo.Response{
		URL:           "https://example.com",
		StatusCode:    200,
		Status:        "200 OK",
		ContentLength: 1234,
		Duration:      100 * time.Millisecond,
		Headers: map[string]string{
			"Content-Type": "text/html",
		},
	}

	err := f.OutputHTTP(resp)
	if err != nil {
		t.Fatalf("OutputHTTP failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if result["url"] != "https://example.com" {
		t.Error("expected url in JSON output")
	}

	if result["statusCode"] != float64(200) {
		t.Error("expected statusCode in JSON output")
	}
}

func TestFormatter_OutputTLS_Text(t *testing.T) {
	buf := new(bytes.Buffer)
	f := NewFormatter("text", buf)

	resp := &tlsinfo.Response{
		Host:        "example.com",
		Port:        "443",
		TLSVersion:  "TLS 1.3",
		CipherSuite: "TLS_AES_256_GCM_SHA384",
		Certificates: []tlsinfo.Certificate{
			{
				Subject: tlsinfo.Subject{
					CommonName:   "example.com",
					Organization: []string{"Example Org"},
					Country:      []string{"US"},
				},
				Issuer: tlsinfo.Subject{
					CommonName:   "Example CA",
					Organization: []string{"CA Org"},
				},
				SerialNumber:       "123456789ABCDEF",
				NotBefore:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:           time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				SignatureAlgorithm: "SHA256-RSA",
				PublicKeyAlgorithm: "RSA",
				PublicKeySize:      2048,
				DNSNames:           []string{"example.com", "www.example.com"},
			},
		},
	}

	err := f.OutputTLS(resp)
	if err != nil {
		t.Fatalf("OutputTLS failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "example.com") {
		t.Error("expected output to contain host")
	}

	if !strings.Contains(output, "TLS 1.3") {
		t.Error("expected output to contain TLS version")
	}

	if !strings.Contains(output, "example.com") {
		t.Error("expected output to contain common name")
	}
}

func TestFormatter_OutputTLS_JSON(t *testing.T) {
	buf := new(bytes.Buffer)
	f := NewFormatter("json", buf)

	resp := &tlsinfo.Response{
		Host:        "example.com",
		Port:        "443",
		TLSVersion:  "TLS 1.3",
		CipherSuite: "TLS_AES_256_GCM_SHA384",
		Certificates: []tlsinfo.Certificate{
			{
				Subject: tlsinfo.Subject{
					CommonName: "example.com",
				},
				NotBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
	}

	err := f.OutputTLS(resp)
	if err != nil {
		t.Fatalf("OutputTLS failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if result["host"] != "example.com" {
		t.Error("expected host in JSON output")
	}

	if result["tlsVersion"] != "TLS 1.3" {
		t.Error("expected tlsVersion in JSON output")
	}
}

func TestFormatter_OutputDNS_Text(t *testing.T) {
	buf := new(bytes.Buffer)
	f := NewFormatter("text", buf)

	resp := &dnsinfo.Response{
		Domain:     "example.com.",
		RecordType: "A",
		Nameserver: "8.8.8.8:53",
		QueryTime:  45 * time.Millisecond,
		Records: []dnsinfo.Record{
			{Type: "A", Value: "93.184.216.34", TTL: 3600},
			{Type: "A", Value: "93.184.216.35", TTL: 3600},
		},
	}

	err := f.OutputDNS(resp)
	if err != nil {
		t.Fatalf("OutputDNS failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "example.com") {
		t.Error("expected output to contain domain")
	}

	if !strings.Contains(output, "93.184.216.34") {
		t.Error("expected output to contain IP address")
	}

	if !strings.Contains(output, "3600") {
		t.Error("expected output to contain TTL")
	}

	if !strings.Contains(output, "8.8.8.8:53") {
		t.Error("expected output to contain nameserver")
	}
}

func TestFormatter_OutputDNS_JSON(t *testing.T) {
	buf := new(bytes.Buffer)
	f := NewFormatter("json", buf)

	resp := &dnsinfo.Response{
		Domain:     "example.com.",
		RecordType: "A",
		Nameserver: "8.8.8.8:53",
		QueryTime:  45 * time.Millisecond,
		Records: []dnsinfo.Record{
			{Type: "A", Value: "93.184.216.34", TTL: 3600},
		},
	}

	err := f.OutputDNS(resp)
	if err != nil {
		t.Fatalf("OutputDNS failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if result["domain"] != "example.com." {
		t.Error("expected domain in JSON output")
	}

	if result["recordType"] != "A" {
		t.Error("expected recordType in JSON output")
	}

	if result["nameserver"] != "8.8.8.8:53" {
		t.Error("expected nameserver in JSON output")
	}
}

func TestFormatter_OutputTLSScan_Text(t *testing.T) {
	buf := new(bytes.Buffer)
	f := NewFormatter("text", buf)

	result := &tlsinfo.TestResult{
		Host: "example.com",
		Port: "443",
		SupportedVersions: map[string]bool{
			"TLS 1.3": true,
			"TLS 1.2": true,
			"TLS 1.1": false,
			"TLS 1.0": false,
		},
		CipherSuites: map[string][]string{
			"TLS 1.3": {"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"},
			"TLS 1.2": {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		},
		PreferredVersion: "TLS 1.3",
		PreferredCipher:  "TLS_AES_256_GCM_SHA384",
		Vulnerabilities:  []string{},
	}

	err := f.OutputTLSScan(result)
	if err != nil {
		t.Fatalf("OutputTLSScan failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "example.com") {
		t.Error("expected output to contain host")
	}

	if !strings.Contains(output, "Supported TLS Versions") {
		t.Error("expected output to contain 'Supported TLS Versions'")
	}

	if !strings.Contains(output, "TLS 1.3: Yes") {
		t.Error("expected output to show TLS 1.3 as supported")
	}

	if !strings.Contains(output, "TLS 1.2: Yes") {
		t.Error("expected output to show TLS 1.2 as supported")
	}

	if !strings.Contains(output, "TLS 1.0: No") {
		t.Error("expected output to show TLS 1.0 as not supported")
	}

	if !strings.Contains(output, "Supported Cipher Suites") {
		t.Error("expected output to contain 'Supported Cipher Suites'")
	}

	if !strings.Contains(output, "TLS_AES_256_GCM_SHA384") {
		t.Error("expected output to contain cipher suite")
	}

	if !strings.Contains(output, "Preferred Version: TLS 1.3") {
		t.Error("expected output to contain preferred version")
	}

	if !strings.Contains(output, "Preferred Cipher: TLS_AES_256_GCM_SHA384") {
		t.Error("expected output to contain preferred cipher")
	}
}

func TestFormatter_OutputTLSScan_JSON(t *testing.T) {
	buf := new(bytes.Buffer)
	f := NewFormatter("json", buf)

	result := &tlsinfo.TestResult{
		Host: "example.com",
		Port: "443",
		SupportedVersions: map[string]bool{
			"TLS 1.3": true,
			"TLS 1.2": true,
			"TLS 1.1": false,
			"TLS 1.0": false,
		},
		PreferredVersion: "TLS 1.3",
	}

	err := f.OutputTLSScan(result)
	if err != nil {
		t.Fatalf("OutputTLSScan failed: %v", err)
	}

	var jsonResult map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &jsonResult); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if jsonResult["host"] != "example.com" {
		t.Error("expected host in JSON output")
	}

	if jsonResult["port"] != "443" {
		t.Error("expected port in JSON output")
	}

	if jsonResult["preferredVersion"] != "TLS 1.3" {
		t.Error("expected preferredVersion in JSON output")
	}
}

func TestFormatter_OutputTLSScan_WithVulnerabilities(t *testing.T) {
	buf := new(bytes.Buffer)
	f := NewFormatter("text", buf)

	result := &tlsinfo.TestResult{
		Host: "example.com",
		Port: "443",
		SupportedVersions: map[string]bool{
			"TLS 1.3": true,
			"TLS 1.2": true,
			"TLS 1.1": true,
			"TLS 1.0": true,
		},
		PreferredVersion: "TLS 1.3",
		Vulnerabilities:  []string{"Server supports deprecated TLS 1.0", "Server supports deprecated TLS 1.1"},
	}

	err := f.OutputTLSScan(result)
	if err != nil {
		t.Fatalf("OutputTLSScan failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "Security Warnings") {
		t.Error("expected output to contain 'Security Warnings'")
	}

	if !strings.Contains(output, "Server supports deprecated TLS 1.0") {
		t.Error("expected output to contain TLS 1.0 warning")
	}

	if !strings.Contains(output, "Server supports deprecated TLS 1.1") {
		t.Error("expected output to contain TLS 1.1 warning")
	}
}

func sampleWHOISRecord() string {
	return strings.TrimSpace(`
Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Updated Date: 2024-01-15T12:00:00Z
Creation Date: 1995-08-04T04:00:00Z
Registry Expiry Date: 2025-08-03T04:00:00Z
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Domain Status: clientTransferProhibited
`)
}
