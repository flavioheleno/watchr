package httpinfo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	timeout := 5 * time.Second
	client := NewClient(timeout, false, false)

	if client == nil {
		t.Fatal("expected non-nil client")
	}

	if client.timeout != timeout {
		t.Errorf("expected timeout %v, got %v", timeout, client.timeout)
	}

	if client.followRedirects {
		t.Error("expected followRedirects to be false")
	}

	if client.showTimings {
		t.Error("expected showTimings to be false")
	}
}

func TestClient_Fetch_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Custom-Header", "test-value")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("Hello, World!")); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(5*time.Second, false, false)
	ctx := context.Background()

	resp, err := client.Fetch(ctx, server.URL)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status code 200, got %d", resp.StatusCode)
	}

	if resp.Status != "200 OK" {
		t.Errorf("expected status '200 OK', got %s", resp.Status)
	}

	if resp.Headers["Content-Type"] != "text/html" {
		t.Errorf("expected Content-Type header 'text/html', got %s", resp.Headers["Content-Type"])
	}

	if resp.Headers["X-Custom-Header"] != "test-value" {
		t.Errorf("expected X-Custom-Header 'test-value', got %s", resp.Headers["X-Custom-Header"])
	}

	if resp.ContentLength != 13 {
		t.Errorf("expected content length 13, got %d", resp.ContentLength)
	}

	if resp.Duration <= 0 {
		t.Error("expected positive duration")
	}

	if !strings.HasPrefix(resp.URL, server.URL) {
		t.Errorf("expected URL to start with %s, got %s", server.URL, resp.URL)
	}
}

func TestClient_Fetch_Redirect(t *testing.T) {
	finalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("Final destination")); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer finalServer.Close()

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, finalServer.URL, http.StatusMovedPermanently)
	}))
	defer redirectServer.Close()

	client := NewClient(5*time.Second, true, false)
	ctx := context.Background()

	resp, err := client.Fetch(ctx, redirectServer.URL)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status code 200, got %d", resp.StatusCode)
	}

	if len(resp.RedirectChain) == 0 {
		t.Error("expected redirect chain to be populated")
	}
}

func TestClient_Fetch_NoRedirect(t *testing.T) {
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com", http.StatusMovedPermanently)
	}))
	defer redirectServer.Close()

	client := NewClient(5*time.Second, false, false)
	ctx := context.Background()

	resp, err := client.Fetch(ctx, redirectServer.URL)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("expected status code 301, got %d", resp.StatusCode)
	}
}

func TestClient_Fetch_InvalidURL(t *testing.T) {
	client := NewClient(5*time.Second, false, false)
	ctx := context.Background()

	_, err := client.Fetch(ctx, "not-a-valid-url")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestClient_Fetch_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(100*time.Millisecond, false, false)
	ctx := context.Background()

	_, err := client.Fetch(ctx, server.URL)
	if err == nil {
		t.Error("expected timeout error")
	}
}
