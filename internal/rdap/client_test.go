package rdap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
