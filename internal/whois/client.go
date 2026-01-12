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
	result, err := c.client.Whois(domain)
	if err != nil {
		return "", err
	}

	return result, nil
}
