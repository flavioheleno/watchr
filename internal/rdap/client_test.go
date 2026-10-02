package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClient_Query(t *testing.T) {
	mockResponse := Response{
		Handle:  "example.com",
		LDHName: "example.com",
		Status:  []string{"active"},
		Events: []Event{
			{
				EventAction: "registration",
				EventDate:   time.Now().AddDate(-5, 0, 0),
			},
			{
				EventAction: "expiration",
				EventDate:   time.Now().AddDate(1, 0, 0),
			},
		},
		Nameservers: []Nameserver{
			{LDHName: "ns1.example.com"},
			{LDHName: "ns2.example.com"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/domain/example.com" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		if err := json.NewEncoder(w).Encode(mockResponse); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(5 * time.Second)
	ctx := context.Background()

	resp, err := client.queryURL(ctx, server.URL+"/domain/example.com")
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if resp.LDHName != "example.com" {
		t.Errorf("expected LDHName example.com, got %s", resp.LDHName)
	}

	if len(resp.Status) != 1 || resp.Status[0] != "active" {
		t.Errorf("expected status [active], got %v", resp.Status)
	}

	if len(resp.Events) != 2 {
		t.Errorf("expected 2 events, got %d", len(resp.Events))
	}

	if len(resp.Nameservers) != 2 {
		t.Errorf("expected 2 nameservers, got %d", len(resp.Nameservers))
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

type requestContextKey struct{}

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func rdapFixture(req *http.Request) *http.Response {
	body := `{"objectClassName":"domain","handle":"EXAMPLE","ldhName":"example.com","status":["active"],"events":[{"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"}],"nameservers":[{"objectClassName":"nameserver","ldhName":"ns.example.com"}]}`
	if strings.HasSuffix(req.URL.Path, "dns.json") {
		body = `{"version":"1.0","publication":"2026-01-01T00:00:00Z","services":[[["com"],["https://rdap.test/"]]]}`
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/rdap+json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: req}
}

func TestQueryDomainProductionContext(t *testing.T) {
	for _, stage := range []string{"canceled", "bootstrap", "domain", "success"} {
		t.Run(stage, func(t *testing.T) {
			client := NewClient(time.Second)
			requests := 0
			client.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				bootstrap := strings.HasSuffix(req.URL.Path, "dns.json")
				if (stage == "bootstrap" && bootstrap) || (stage == "domain" && !bootstrap) {
					if req.Context().Value(requestContextKey{}) == "request" {
						<-req.Context().Done()
						return nil, req.Context().Err()
					}
				}
				return rdapFixture(req), nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if stage == "canceled" {
				cancel()
			}
			resp, err := client.QueryDomain(context.WithValue(ctx, requestContextKey{}, "request"), " EXAMPLE.COM ")
			switch stage {
			case "canceled":
				if !errors.Is(err, context.Canceled) || requests != 0 {
					t.Fatalf("cancellation ignored: requests=%d err=%v", requests, err)
				}
			case "success":
				if err != nil {
					t.Fatal(err)
				}
				if resp.LDHName != "example.com" || len(resp.Events) != 1 || len(resp.Nameservers) != 1 {
					t.Fatalf("incorrect response: %+v", resp)
				}
			default:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("deadline lost at %s: %v", stage, err)
				}
			}
		})
	}
}

func TestClient_QueryDomain_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		if _, err := w.Write([]byte("not found")); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer server.Close()

	client := &Client{
		httpClient: &http.Client{Timeout: 5 * time.Second},
		baseURL:    server.URL,
	}
	ctx := context.Background()

	_, err := client.QueryDomain(ctx, "nonexistent.com")
	if err == nil {
		t.Fatal("expected error for not found domain")
	}
}
