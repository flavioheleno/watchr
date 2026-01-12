package whois

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	timeout := 5 * time.Second
	client := NewClient(timeout)

	if client == nil {
		t.Fatal("expected non-nil client")
	}

	if client.timeout != timeout {
		t.Errorf("expected timeout %v, got %v", timeout, client.timeout)
	}
}

func TestClient_Query(t *testing.T) {
	client := NewClient(10 * time.Second)
	ctx := context.Background()

	result, err := client.Query(ctx, "example.com")
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if result == "" {
		t.Error("expected non-empty result")
	}

	if !strings.Contains(strings.ToLower(result), "domain") {
		t.Error("expected result to contain 'domain'")
	}
}

func TestClient_Query_InvalidDomain(t *testing.T) {
	client := NewClient(5 * time.Second)
	ctx := context.Background()

	result, err := client.Query(ctx, "invalid..domain")
	if err == nil && result == "" {
		t.Error("expected error or empty result for invalid domain")
	}
}
