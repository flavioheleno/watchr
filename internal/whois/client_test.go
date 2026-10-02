package whois

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	whoislib "github.com/likexian/whois"
)

type fixtureDialer struct{ queries chan string }

func (d fixtureDialer) Dial(_, address string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }()
		query, err := bufio.NewReader(server).ReadString('\n')
		if err != nil {
			return
		}
		d.queries <- strings.TrimSpace(query)
		response := "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar\n"
		if address == "whois.iana.org:43" {
			response = "whois: registry.test\n"
		}
		_, _ = fmt.Fprint(server, response)
	}()
	return client, nil
}

func TestClientQuery(t *testing.T) {
	queries := make(chan string, 4)
	client := NewClient(time.Second)
	client.client.SetDialer(fixtureDialer{queries: queries})
	data, err := client.Query(context.Background(), " EXAMPLE.COM ")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(data, "Domain Name: EXAMPLE.COM") {
		t.Fatalf("unexpected result: %s", data)
	}
	if got := <-queries; got != "com" {
		t.Fatalf("unexpected bootstrap query: %s", got)
	}
	if got := <-queries; got != "example.com" {
		t.Fatalf("domain not normalized: %s", got)
	}
}

func TestClientQueryEmptyDomain(t *testing.T) {
	_, err := NewClient(time.Second).Query(context.Background(), " ")
	if !errors.Is(err, whoislib.ErrDomainEmpty) {
		t.Fatalf("expected empty domain error, got %v", err)
	}
}

func TestClientQueryCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewClient(time.Second).Query(ctx, "")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
