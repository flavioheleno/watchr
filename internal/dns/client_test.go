package dns

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	timeout := 5 * time.Second
	nameserver := "8.8.8.8:53"

	client := NewClient(timeout, nameserver)

	if client == nil {
		t.Fatal("expected non-nil client")
	}

	if client.timeout != timeout {
		t.Errorf("expected timeout %v, got %v", timeout, client.timeout)
	}

	if client.nameserver != nameserver {
		t.Errorf("expected nameserver %s, got %s", nameserver, client.nameserver)
	}
}

func TestClient_Query_A(t *testing.T) {
	client := NewClient(10*time.Second, "8.8.8.8:53")
	ctx := context.Background()

	resp, err := client.Query(ctx, "example.com", "A")
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if resp.Domain != "example.com." && resp.Domain != "example.com" {
		t.Errorf("expected domain 'example.com' or 'example.com.', got %s", resp.Domain)
	}

	if resp.RecordType != "A" {
		t.Errorf("expected record type 'A', got %s", resp.RecordType)
	}

	if len(resp.Records) == 0 {
		t.Error("expected at least one A record")
	}

	for _, record := range resp.Records {
		if record.Type != "A" {
			t.Errorf("expected record type 'A', got %s", record.Type)
		}
		if record.Value == "" {
			t.Error("expected non-empty record value")
		}
		if record.TTL == 0 {
			t.Error("expected non-zero TTL")
		}
	}

	if resp.QueryTime == 0 {
		t.Error("expected non-zero query time")
	}
}

func TestClient_Query_AAAA(t *testing.T) {
	client := NewClient(10*time.Second, "8.8.8.8:53")
	ctx := context.Background()

	resp, err := client.Query(ctx, "example.com", "AAAA")
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if resp.RecordType != "AAAA" {
		t.Errorf("expected record type 'AAAA', got %s", resp.RecordType)
	}

	if len(resp.Records) == 0 {
		t.Error("expected at least one AAAA record for example.com")
	}
}

func TestClient_Query_MX(t *testing.T) {
	client := NewClient(10*time.Second, "8.8.8.8:53")
	ctx := context.Background()

	resp, err := client.Query(ctx, "example.com", "MX")
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if resp.RecordType != "MX" {
		t.Errorf("expected record type 'MX', got %s", resp.RecordType)
	}

	if len(resp.Records) == 0 {
		t.Error("expected at least one MX record for example.com")
	}

	for _, record := range resp.Records {
		if record.Type != "MX" {
			t.Errorf("expected record type 'MX', got %s", record.Type)
		}
	}
}

func TestClient_Query_NS(t *testing.T) {
	client := NewClient(10*time.Second, "8.8.8.8:53")
	ctx := context.Background()

	resp, err := client.Query(ctx, "example.com", "NS")
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if resp.RecordType != "NS" {
		t.Errorf("expected record type 'NS', got %s", resp.RecordType)
	}

	if len(resp.Records) == 0 {
		t.Error("expected at least one NS record")
	}
}

func TestClient_Query_TXT(t *testing.T) {
	client := NewClient(10*time.Second, "8.8.8.8:53")
	ctx := context.Background()

	resp, err := client.Query(ctx, "example.com", "TXT")
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if resp.RecordType != "TXT" {
		t.Errorf("expected record type 'TXT', got %s", resp.RecordType)
	}
}

func TestClient_Query_CNAME(t *testing.T) {
	client := NewClient(10*time.Second, "8.8.8.8:53")
	ctx := context.Background()

	resp, err := client.Query(ctx, "www.example.com", "CNAME")
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if resp.RecordType != "CNAME" {
		t.Errorf("expected record type 'CNAME', got %s", resp.RecordType)
	}
}

func TestClient_Query_InvalidDomain(t *testing.T) {
	client := NewClient(5*time.Second, "8.8.8.8:53")
	ctx := context.Background()

	resp, err := client.Query(ctx, "this-domain-absolutely-does-not-exist-123456789.com", "A")

	if err == nil && len(resp.Records) > 0 {
		t.Error("expected error or empty records for non-existent domain")
	}
}

func TestClient_Query_Timeout(t *testing.T) {
	client := NewClient(1*time.Millisecond, "8.8.8.8:53")
	ctx := context.Background()

	_, err := client.Query(ctx, "example.com", "A")
	if err == nil {
		t.Error("expected timeout error")
	}

	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline") {
		t.Logf("got error: %v (expected timeout/deadline)", err)
	}
}

func TestClient_Query_InvalidRecordType(t *testing.T) {
	client := NewClient(5*time.Second, "8.8.8.8:53")
	ctx := context.Background()

	_, err := client.Query(ctx, "example.com", "INVALID")
	if err == nil {
		t.Error("expected error for invalid record type")
	}
}

func TestClient_Query_CustomNameserver(t *testing.T) {
	client := NewClient(10*time.Second, "1.1.1.1:53")
	ctx := context.Background()

	resp, err := client.Query(ctx, "example.com", "A")
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if resp.Nameserver != "1.1.1.1:53" {
		t.Errorf("expected nameserver '1.1.1.1:53', got %s", resp.Nameserver)
	}

	if len(resp.Records) == 0 {
		t.Error("expected at least one A record")
	}
}
