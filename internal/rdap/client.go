package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	rdaplib "github.com/registrobr/rdap"
	"github.com/registrobr/rdap/protocol"
)

type Client struct {
	httpClient *http.Client
	baseURL    string
	rdapClient *rdaplib.Client
}

func NewClient(timeout time.Duration) *Client {
	httpClient := &http.Client{
		Timeout: timeout,
	}

	rdapClient := &rdaplib.Client{
		Transport: rdaplib.NewBootstrapFetcher(httpClient, rdaplib.IANABootstrap, nil),
	}

	return &Client{
		httpClient: httpClient,
		rdapClient: rdapClient,
	}
}

func (c *Client) queryURL(ctx context.Context, url string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/rdap+json")

	slog.Debug("querying RDAP URL", "url", url)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("RDAP query failed with status %d: %s", resp.StatusCode, string(body))
	}

	var rdapResp Response
	if err := json.NewDecoder(resp.Body).Decode(&rdapResp); err != nil {
		return nil, fmt.Errorf("failed to decode RDAP response: %w", err)
	}

	return &rdapResp, nil
}

func (c *Client) QueryDomain(ctx context.Context, domain string) (*Response, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	if c.baseURL != "" {
		url := fmt.Sprintf("%s/domain/%s", strings.TrimSuffix(c.baseURL, "/"), domain)
		return c.queryURL(ctx, url)
	}

	slog.Debug("querying domain", "domain", domain)
	domainObj, _, err := c.rdapClient.Domain(domain, nil, nil)
	if err != nil {
		return nil, err
	}

	return convertDomainToResponse(domainObj), nil
}

func convertDomainToResponse(d *protocol.Domain) *Response {
	resp := &Response{
		Handle:  d.Handle,
		LDHName: d.LDHName,
	}

	for _, status := range d.Status {
		resp.Status = append(resp.Status, string(status))
	}

	for _, entity := range d.Entities {
		resp.Entities = append(resp.Entities, Entity{
			Handle:     entity.Handle,
			Roles:      entity.Roles,
			VCardArray: entity.VCardArray,
		})
	}

	for _, event := range d.Events {
		resp.Events = append(resp.Events, Event{
			EventAction: string(event.Action),
			EventDate:   event.Date.Time,
		})
	}

	for _, link := range d.Links {
		resp.Links = append(resp.Links, Link{
			Value: link.Value,
			Rel:   link.Rel,
			Href:  link.Href,
			Type:  link.Type,
		})
	}

	for _, ns := range d.Nameservers {
		resp.Nameservers = append(resp.Nameservers, Nameserver{
			LDHName:         ns.LDHName,
			ObjectClassName: ns.ObjectClassName,
		})
	}

	if d.SecureDNS != nil {
		resp.SecureDNS = &SecureDNS{
			DelegationSigned: d.SecureDNS.DelegationSigned,
		}
	}

	return resp
}
