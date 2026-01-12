package httpinfo

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptrace"
	"time"
)

type Client struct {
	timeout         time.Duration
	followRedirects bool
	showTimings     bool
	httpClient      *http.Client
	redirectChain   []string
}

func NewClient(timeout time.Duration, followRedirects bool, showTimings bool) *Client {
	client := &Client{
		timeout:         timeout,
		followRedirects: followRedirects,
		showTimings:     showTimings,
		redirectChain:   make([]string, 0),
	}

	httpClient := &http.Client{
		Timeout: timeout,
	}

	if !followRedirects {
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			client.redirectChain = append(client.redirectChain, req.URL.String())
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		}
	}

	client.httpClient = httpClient
	return client
}

func (c *Client) Fetch(ctx context.Context, url string) (*Response, error) {
	c.redirectChain = make([]string, 0)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "watchr/1.0")

	var timings *Timings
	if c.showTimings {
		timings = &Timings{}

		var dnsStart, connectStart, tlsStart time.Time

		trace := &httptrace.ClientTrace{
			DNSStart: func(_ httptrace.DNSStartInfo) {
				dnsStart = time.Now()
			},
			DNSDone: func(_ httptrace.DNSDoneInfo) {
				if !dnsStart.IsZero() {
					timings.DNSLookup = time.Since(dnsStart)
				}
			},
			ConnectStart: func(_, _ string) {
				connectStart = time.Now()
			},
			ConnectDone: func(_, _ string, _ error) {
				if !connectStart.IsZero() {
					timings.TCPConnection = time.Since(connectStart)
				}
			},
			TLSHandshakeStart: func() {
				tlsStart = time.Now()
			},
			TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
				if !tlsStart.IsZero() {
					timings.TLSHandshake = time.Since(tlsStart)
				}
			},
		}

		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	}

	slog.Debug("fetching URL", "url", url)
	start := time.Now()
	resp, err := c.httpClient.Do(req)

	if err != nil {
		return nil, err
	}

	// Read the body to measure content transfer time
	var contentTransferStart time.Time
	if c.showTimings && timings != nil {
		contentTransferStart = time.Now()
	}

	_, readErr := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	duration := time.Since(start)

	if readErr != nil {
		return nil, readErr
	}

	// Calculate timing breakdowns
	if c.showTimings && timings != nil {
		timings.Total = duration

		if !contentTransferStart.IsZero() {
			timings.ContentTransfer = time.Since(contentTransferStart)

			// Server processing = total - (dns + tcp + tls + content transfer)
			overhead := timings.DNSLookup + timings.TCPConnection + timings.TLSHandshake + timings.ContentTransfer
			if duration > overhead {
				timings.ServerProcessing = duration - overhead
			}
		}
	}

	response := &Response{
		URL:              resp.Request.URL.String(),
		StatusCode:       resp.StatusCode,
		Status:           resp.Status,
		Headers:          make(map[string]string),
		ContentLength:    resp.ContentLength,
		TransferEncoding: resp.TransferEncoding,
		Duration:         duration,
		Timings:          timings,
		RedirectChain:    c.redirectChain,
	}

	for key, values := range resp.Header {
		if len(values) > 0 {
			response.Headers[key] = values[0]
		}
	}

	if resp.TLS != nil {
		response.TLSVersion = tlsVersionString(resp.TLS.Version)
		response.TLSCipherSuite = tls.CipherSuiteName(resp.TLS.CipherSuite)
	}

	return response, nil
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
