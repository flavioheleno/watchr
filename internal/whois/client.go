package whois

import (
	"context"
	"log/slog"
	"strings"
	"time"

	whoislib "github.com/likexian/whois"
)

type Client struct {
	timeout time.Duration
	client  *whoislib.Client
}

func NewClient(timeout time.Duration) *Client {
	client := whoislib.NewClient()
	client.SetTimeout(timeout)

	return &Client{
		timeout: timeout,
		client:  client,
	}
}

func (c *Client) Query(ctx context.Context, domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	slog.Debug("querying WHOIS", "domain", domain)

	// Run WHOIS query in a goroutine to respect context cancellation
	type result struct {
		data string
		err  error
	}
	resultCh := make(chan result, 1)

	go func() {
		data, err := c.client.Whois(domain)
		resultCh <- result{data: data, err: err}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-resultCh:
		return res.data, res.err
	}
}
