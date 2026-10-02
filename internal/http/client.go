package httpinfo

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"
)

type Client struct {
	timeout         time.Duration
	followRedirects bool
	showTimings     bool
	httpClient      *http.Client
	redirectChain   []string
	redirectMu      sync.Mutex
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
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	if !followRedirects {
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			client.redirectMu.Lock()
			client.redirectChain = append(client.redirectChain, req.URL.String())
			client.redirectMu.Unlock()
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
	c.redirectMu.Lock()
	c.redirectChain = make([]string, 0)
	c.redirectMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "github.com/flavioheleno/watchr/1.0")

	var timingData *requestTimings
	if c.showTimings {
		timingData = &requestTimings{connectStarts: make(map[string]time.Time)}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), timingData.trace()))
	}

	slog.Debug("fetching URL", "url", url)
	start := time.Now()
	resp, err := c.httpClient.Do(req)

	if err != nil {
		return nil, err
	}

	contentTransferStart := time.Now()
	_, readErr := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	duration := time.Since(start)
	if readErr != nil {
		return nil, readErr
	}

	var timings *Timings
	if timingData != nil {
		snapshot := timingData.snapshot()
		snapshot.Total = duration
		snapshot.ContentTransfer = time.Since(contentTransferStart)
		timings = &snapshot
	}

	c.redirectMu.Lock()
	redirectChainCopy := make([]string, len(c.redirectChain))
	copy(redirectChainCopy, c.redirectChain)
	c.redirectMu.Unlock()

	response := &Response{
		URL:              resp.Request.URL.String(),
		StatusCode:       resp.StatusCode,
		Status:           resp.Status,
		Headers:          resp.Header.Clone(),
		ContentLength:    resp.ContentLength,
		TransferEncoding: resp.TransferEncoding,
		Duration:         duration,
		Timings:          timings,
		RedirectChain:    redirectChainCopy,
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
