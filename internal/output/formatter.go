package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/likexian/whois-parser"

	dnsinfo "watchr/internal/dns"
	httpinfo "watchr/internal/http"
	"watchr/internal/rdap"
	tlsinfo "watchr/internal/tls"
)

type Formatter struct {
	format string
	writer io.Writer
}

func NewFormatter(format string, writer io.Writer) *Formatter {
	return &Formatter{
		format: format,
		writer: writer,
	}
}

func writeLine(w io.Writer, format string, args ...interface{}) error {
	_, err := fmt.Fprintf(w, format, args...)
	return err
}

func (f *Formatter) OutputRDAP(resp *rdap.Response) error {
	switch f.format {
	case "json":
		return f.outputJSON(resp)
	default:
		return f.outputRDAPText(resp)
	}
}

func (f *Formatter) OutputWHOIS(data string) error {
	parsed, err := whoisparser.Parse(data)
	if err != nil || parsed.Domain == nil {
		return f.outputWHOISUnparsed(data)
	}

	if f.format == "json" {
		payload := map[string]interface{}{
			"source": "WHOIS",
			"raw":    data,
			"parsed": parsed,
		}
		return f.outputJSON(payload)
	}

	return f.outputWHOISTextParsed(parsed, data)
}

func (f *Formatter) outputJSON(data interface{}) error {
	encoder := json.NewEncoder(f.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func (f *Formatter) outputRDAPText(resp *rdap.Response) error {
	if err := writeLine(f.writer, "Domain: %s\n", resp.LDHName); err != nil {
		return err
	}
	if err := writeLine(f.writer, "Handle: %s\n", resp.Handle); err != nil {
		return err
	}

	if len(resp.Status) > 0 {
		if err := writeLine(f.writer, "Status: %v\n", resp.Status); err != nil {
			return err
		}
	}

	if len(resp.Events) > 0 {
		if err := writeLine(f.writer, "\nEvents:\n"); err != nil {
			return err
		}
		for _, event := range resp.Events {
			if err := writeLine(f.writer, "  %s: %s\n", event.EventAction, event.EventDate.Format(time.RFC3339)); err != nil {
				return err
			}
		}
	}

	if len(resp.Nameservers) > 0 {
		if err := writeLine(f.writer, "\nNameservers:\n"); err != nil {
			return err
		}
		for _, ns := range resp.Nameservers {
			if err := writeLine(f.writer, "  %s\n", ns.LDHName); err != nil {
				return err
			}
		}
	}

	return writeLine(f.writer, "\nSource: RDAP\n")
}

func (f *Formatter) outputWHOISTextRaw(data string) error {
	if err := writeLine(f.writer, "%s\n", data); err != nil {
		return err
	}
	return writeLine(f.writer, "\nSource: WHOIS\n")
}

func (f *Formatter) outputWHOISUnparsed(data string) error {
	if f.format == "json" {
		payload := map[string]string{
			"source": "WHOIS",
			"data":   data,
		}
		return f.outputJSON(payload)
	}
	return f.outputWHOISTextRaw(data)
}

func (f *Formatter) outputWHOISTextParsed(info whoisparser.WhoisInfo, raw string) error {
	if info.Domain != nil {
		if err := writeLine(f.writer, "Domain: %s\n", info.Domain.Domain); err != nil {
			return err
		}
		if info.Domain.WhoisServer != "" {
			if err := writeLine(f.writer, "WHOIS Server: %s\n", info.Domain.WhoisServer); err != nil {
				return err
			}
		}
		if len(info.Domain.Status) > 0 {
			if err := writeLine(f.writer, "Status: %s\n", strings.Join(info.Domain.Status, ", ")); err != nil {
				return err
			}
		}
		if len(info.Domain.NameServers) > 0 {
			if err := writeLine(f.writer, "Name Servers: %s\n", strings.Join(info.Domain.NameServers, ", ")); err != nil {
				return err
			}
		}
		if info.Domain.CreatedDate != "" {
			if err := writeLine(f.writer, "Created: %s\n", info.Domain.CreatedDate); err != nil {
				return err
			}
		}
		if info.Domain.UpdatedDate != "" {
			if err := writeLine(f.writer, "Updated: %s\n", info.Domain.UpdatedDate); err != nil {
				return err
			}
		}
		if info.Domain.ExpirationDate != "" {
			if err := writeLine(f.writer, "Expires: %s\n", info.Domain.ExpirationDate); err != nil {
				return err
			}
		}
	}

	if registrar := contactDisplayName(info.Registrar); registrar != "" {
		if err := writeLine(f.writer, "Registrar: %s\n", registrar); err != nil {
			return err
		}
	}

	if err := writeContactSection(f.writer, "Registrant", info.Registrant); err != nil {
		return err
	}
	if err := writeContactSection(f.writer, "Administrative Contact", info.Administrative); err != nil {
		return err
	}
	if err := writeContactSection(f.writer, "Technical Contact", info.Technical); err != nil {
		return err
	}

	if err := writeLine(f.writer, "\nRaw WHOIS:\n%s\n", raw); err != nil {
		return err
	}
	return writeLine(f.writer, "\nSource: WHOIS\n")
}

func (f *Formatter) OutputHTTP(resp *httpinfo.Response) error {
	switch f.format {
	case "json":
		return f.outputHTTPJSON(resp)
	default:
		return f.outputHTTPText(resp)
	}
}

func (f *Formatter) outputHTTPJSON(resp *httpinfo.Response) error {
	// Create a JSON-friendly representation
	jsonResp := map[string]interface{}{
		"url":        resp.URL,
		"statusCode": resp.StatusCode,
		"status":     resp.Status,
		"headers":    resp.Headers,
		"duration":   resp.Duration,
	}

	// Handle content length
	if resp.ContentLength >= 0 {
		jsonResp["contentLength"] = resp.ContentLength
	} else {
		// ContentLength is -1, check if chunked
		isChunked := false
		for _, enc := range resp.TransferEncoding {
			if enc == "chunked" {
				isChunked = true
				break
			}
		}
		if isChunked {
			jsonResp["contentLength"] = "chunked"
		} else {
			jsonResp["contentLength"] = "unknown"
		}
	}

	// Add transfer encoding if present
	if len(resp.TransferEncoding) > 0 {
		jsonResp["transferEncoding"] = resp.TransferEncoding
	}

	// Add timing breakdown if present
	if resp.Timings != nil {
		jsonResp["timings"] = resp.Timings
	}

	// Add TLS info if present
	if resp.TLSVersion != "" {
		jsonResp["tlsVersion"] = resp.TLSVersion
		jsonResp["tlsCipherSuite"] = resp.TLSCipherSuite
	}

	// Add redirect chain if present
	if len(resp.RedirectChain) > 0 {
		jsonResp["redirectChain"] = resp.RedirectChain
	}

	return f.outputJSON(jsonResp)
}

func (f *Formatter) outputHTTPText(resp *httpinfo.Response) error {
	if err := writeLine(f.writer, "URL: %s\n", resp.URL); err != nil {
		return err
	}
	if err := writeLine(f.writer, "Status: %s\n", resp.Status); err != nil {
		return err
	}
	if err := writeLine(f.writer, "Status Code: %d\n", resp.StatusCode); err != nil {
		return err
	}

	// Handle content length display
	if resp.ContentLength >= 0 {
		if err := writeLine(f.writer, "Content Length: %d bytes\n", resp.ContentLength); err != nil {
			return err
		}
	} else {
		// ContentLength is -1, check if chunked
		isChunked := false
		for _, enc := range resp.TransferEncoding {
			if enc == "chunked" {
				isChunked = true
				break
			}
		}
		if isChunked {
			if err := writeLine(f.writer, "Content Length: chunked\n"); err != nil {
				return err
			}
		} else {
			if err := writeLine(f.writer, "Content Length: unknown\n"); err != nil {
				return err
			}
		}
	}

	if err := writeLine(f.writer, "Response Time: %v\n", resp.Duration); err != nil {
		return err
	}

	// Display timing breakdown if available
	if resp.Timings != nil {
		if err := writeLine(f.writer, "\nTiming Breakdown:\n"); err != nil {
			return err
		}
		if resp.Timings.DNSLookup > 0 {
			if err := writeLine(f.writer, "  DNS Lookup:        %v\n", resp.Timings.DNSLookup); err != nil {
				return err
			}
		}
		if resp.Timings.TCPConnection > 0 {
			if err := writeLine(f.writer, "  TCP Connection:    %v\n", resp.Timings.TCPConnection); err != nil {
				return err
			}
		}
		if resp.Timings.TLSHandshake > 0 {
			if err := writeLine(f.writer, "  TLS Handshake:     %v\n", resp.Timings.TLSHandshake); err != nil {
				return err
			}
		}
		if resp.Timings.ServerProcessing > 0 {
			if err := writeLine(f.writer, "  Server Processing: %v\n", resp.Timings.ServerProcessing); err != nil {
				return err
			}
		}
		if resp.Timings.ContentTransfer > 0 {
			if err := writeLine(f.writer, "  Content Transfer:  %v\n", resp.Timings.ContentTransfer); err != nil {
				return err
			}
		}
		if err := writeLine(f.writer, "  Total:             %v\n", resp.Timings.Total); err != nil {
			return err
		}
	}

	if resp.TLSVersion != "" {
		if err := writeLine(f.writer, "\nTLS Information:\n"); err != nil {
			return err
		}
		if err := writeLine(f.writer, "  Version: %s\n", resp.TLSVersion); err != nil {
			return err
		}
		if err := writeLine(f.writer, "  Cipher Suite: %s\n", resp.TLSCipherSuite); err != nil {
			return err
		}
	}

	if len(resp.RedirectChain) > 0 {
		if err := writeLine(f.writer, "\nRedirect Chain:\n"); err != nil {
			return err
		}
		for i, url := range resp.RedirectChain {
			if err := writeLine(f.writer, "  %d. %s\n", i+1, url); err != nil {
				return err
			}
		}
	}

	if len(resp.Headers) > 0 {
		if err := writeLine(f.writer, "\nHeaders:\n"); err != nil {
			return err
		}
		for key, value := range resp.Headers {
			if err := writeLine(f.writer, "  %s: %s\n", key, value); err != nil {
				return err
			}
		}
	}

	return nil
}

func (f *Formatter) OutputTLS(resp *tlsinfo.Response) error {
	switch f.format {
	case "json":
		return f.outputJSON(resp)
	default:
		return f.outputTLSText(resp)
	}
}

func (f *Formatter) outputTLSText(resp *tlsinfo.Response) error {
	if err := writeLine(f.writer, "Host: %s:%s\n", resp.Host, resp.Port); err != nil {
		return err
	}
	if err := writeLine(f.writer, "TLS Version: %s\n", resp.TLSVersion); err != nil {
		return err
	}
	if err := writeLine(f.writer, "Cipher Suite: %s\n", resp.CipherSuite); err != nil {
		return err
	}

	if len(resp.Certificates) > 0 {
		if err := writeLine(f.writer, "\nCertificate Chain (%d certificates):\n", len(resp.Certificates)); err != nil {
			return err
		}

		for i, cert := range resp.Certificates {
			if err := writeLine(f.writer, "\nCertificate #%d:\n", i+1); err != nil {
				return err
			}
			if err := writeLine(f.writer, "  Subject:\n"); err != nil {
				return err
			}
			if err := writeLine(f.writer, "    Common Name: %s\n", cert.Subject.CommonName); err != nil {
				return err
			}

			if len(cert.Subject.Organization) > 0 {
				if err := writeLine(f.writer, "    Organization: %s\n", strings.Join(cert.Subject.Organization, ", ")); err != nil {
					return err
				}
			}
			if len(cert.Subject.OrganizationalUnit) > 0 {
				if err := writeLine(f.writer, "    Organizational Unit: %s\n", strings.Join(cert.Subject.OrganizationalUnit, ", ")); err != nil {
					return err
				}
			}
			if len(cert.Subject.Country) > 0 {
				if err := writeLine(f.writer, "    Country: %s\n", strings.Join(cert.Subject.Country, ", ")); err != nil {
					return err
				}
			}

			if err := writeLine(f.writer, "  Issuer:\n"); err != nil {
				return err
			}
			if err := writeLine(f.writer, "    Common Name: %s\n", cert.Issuer.CommonName); err != nil {
				return err
			}
			if len(cert.Issuer.Organization) > 0 {
				if err := writeLine(f.writer, "    Organization: %s\n", strings.Join(cert.Issuer.Organization, ", ")); err != nil {
					return err
				}
			}

			if err := writeLine(f.writer, "  Validity:\n"); err != nil {
				return err
			}
			if err := writeLine(f.writer, "    Not Before: %s\n", cert.NotBefore.Format(time.RFC3339)); err != nil {
				return err
			}
			if err := writeLine(f.writer, "    Not After: %s\n", cert.NotAfter.Format(time.RFC3339)); err != nil {
				return err
			}

			if err := writeLine(f.writer, "  Serial Number: %s\n", cert.SerialNumber); err != nil {
				return err
			}
			if err := writeLine(f.writer, "  Signature Algorithm: %s\n", cert.SignatureAlgorithm); err != nil {
				return err
			}
			if err := writeLine(f.writer, "  Public Key: %s (%d bits)\n", cert.PublicKeyAlgorithm, cert.PublicKeySize); err != nil {
				return err
			}

			if len(cert.DNSNames) > 0 {
				if err := writeLine(f.writer, "  DNS Names:\n"); err != nil {
					return err
				}
				for _, name := range cert.DNSNames {
					if err := writeLine(f.writer, "    - %s\n", name); err != nil {
						return err
					}
				}
			}

			if cert.IsCA {
				if err := writeLine(f.writer, "  CA Certificate: Yes\n"); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (f *Formatter) OutputTLSScan(result *tlsinfo.TestResult) error {
	switch f.format {
	case "json":
		return f.outputJSON(result)
	default:
		return f.outputTLSScanText(result)
	}
}

func (f *Formatter) outputTLSScanText(result *tlsinfo.TestResult) error {
	if err := writeLine(f.writer, "Host: %s:%s\n", result.Host, result.Port); err != nil {
		return err
	}

	if err := writeLine(f.writer, "\nSupported TLS Versions:\n"); err != nil {
		return err
	}
	versions := []string{"TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"}
	for _, version := range versions {
		supported := result.SupportedVersions[version]
		status := "No"
		if supported {
			status = "Yes"
		}
		if err := writeLine(f.writer, "  %s: %s\n", version, status); err != nil {
			return err
		}
	}

	if result.PreferredVersion != "" {
		if err := writeLine(f.writer, "\nPreferred Version: %s\n", result.PreferredVersion); err != nil {
			return err
		}
	}

	if len(result.CipherSuites) > 0 {
		if err := writeLine(f.writer, "\nSupported Cipher Suites:\n"); err != nil {
			return err
		}
		for _, version := range versions {
			suites := result.CipherSuites[version]
			if len(suites) > 0 {
				if err := writeLine(f.writer, "\n  %s:\n", version); err != nil {
					return err
				}
				for _, suite := range suites {
					if err := writeLine(f.writer, "    - %s\n", suite); err != nil {
						return err
					}
				}
			}
		}
	}

	if result.PreferredCipher != "" {
		if err := writeLine(f.writer, "\nPreferred Cipher: %s\n", result.PreferredCipher); err != nil {
			return err
		}
	}

	if len(result.Vulnerabilities) > 0 {
		if err := writeLine(f.writer, "\nSecurity Warnings:\n"); err != nil {
			return err
		}
		for _, vuln := range result.Vulnerabilities {
			if err := writeLine(f.writer, "  ! %s\n", vuln); err != nil {
				return err
			}
		}
	}

	return nil
}

func (f *Formatter) OutputDNS(resp *dnsinfo.Response) error {
	switch f.format {
	case "json":
		return f.outputJSON(resp)
	default:
		return f.outputDNSText(resp)
	}
}

func (f *Formatter) outputDNSText(resp *dnsinfo.Response) error {
	if err := writeLine(f.writer, "Domain: %s\n", resp.Domain); err != nil {
		return err
	}
	if err := writeLine(f.writer, "Record Type: %s\n", resp.RecordType); err != nil {
		return err
	}
	if err := writeLine(f.writer, "Nameserver: %s\n", resp.Nameserver); err != nil {
		return err
	}
	if err := writeLine(f.writer, "Query Time: %v\n", resp.QueryTime); err != nil {
		return err
	}

	if len(resp.Records) > 0 {
		if err := writeLine(f.writer, "\nRecords (%d):\n", len(resp.Records)); err != nil {
			return err
		}
		for _, record := range resp.Records {
			if err := writeLine(f.writer, "  %-6s  %-40s  TTL: %d\n", record.Type, record.Value, record.TTL); err != nil {
				return err
			}
		}
	} else {
		if err := writeLine(f.writer, "\nNo records found\n"); err != nil {
			return err
		}
	}

	return nil
}

func contactDisplayName(contact *whoisparser.Contact) string {
	if contact == nil {
		return ""
	}

	if contact.Organization != "" {
		return contact.Organization
	}

	return contact.Name
}

func writeContactSection(writer io.Writer, title string, contact *whoisparser.Contact) error {
	if contact == nil {
		return nil
	}

	lines := make([]string, 0)

	if contact.Name != "" {
		lines = append(lines, fmt.Sprintf("Name: %s", contact.Name))
	}
	if contact.Organization != "" {
		lines = append(lines, fmt.Sprintf("Organization: %s", contact.Organization))
	}
	if contact.Email != "" {
		lines = append(lines, fmt.Sprintf("Email: %s", contact.Email))
	}
	location := strings.TrimSpace(strings.Join(filterEmpty([]string{
		contact.City,
		contact.Province,
		contact.Country,
	}), ", "))
	if location != "" {
		lines = append(lines, fmt.Sprintf("Location: %s", location))
	}
	if contact.Phone != "" {
		lines = append(lines, fmt.Sprintf("Phone: %s", contact.Phone))
	}

	if len(lines) == 0 {
		return nil
	}

	if err := writeLine(writer, "\n%s:\n", title); err != nil {
		return err
	}
	for _, line := range lines {
		if err := writeLine(writer, "  %s\n", line); err != nil {
			return err
		}
	}

	return nil
}

func filterEmpty(values []string) []string {
	result := make([]string, 0, len(values))
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			result = append(result, v)
		}
	}
	return result
}
