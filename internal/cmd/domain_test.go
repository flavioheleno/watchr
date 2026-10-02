package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/flavioheleno/watchr/internal/rdap"
)

func TestDomainCommandQueries(t *testing.T) {
	queryError := errors.New("query failed")
	for _, tt := range []struct {
		name                  string
		rdapFails, whoisFails bool
		format, want          string
	}{
		{"RDAP text", false, false, "text", "Source: RDAP"},
		{"RDAP JSON", false, false, "json", "\"ldhName\": \"example.com\""},
		{"WHOIS text", true, false, "text", "Source: WHOIS"},
		{"WHOIS JSON", true, false, "json", "\"source\": \"WHOIS\""},
		{"both fail", true, true, "text", "both RDAP and WHOIS"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rdapCalls, whoisCalls := 0, 0
			root := NewRootCommand()
			old, _, err := root.Find([]string{"domain"})
			if err != nil {
				t.Fatal(err)
			}
			root.RemoveCommand(old)
			root.AddCommand(newDomainCommand(
				func(ctx context.Context, domain string, timeout time.Duration) (*rdap.Response, error) {
					rdapCalls++
					if domain != "example.com" || timeout != 10*time.Second || ctx == nil {
						t.Fatalf("incorrect query options: %s %v", domain, timeout)
					}
					if tt.rdapFails {
						return nil, queryError
					}
					return &rdap.Response{LDHName: domain}, nil
				},
				func(context.Context, string, time.Duration) (string, error) {
					whoisCalls++
					if tt.whoisFails {
						return "", queryError
					}
					return "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar\n", nil
				},
			))
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs([]string{"domain", "example.com", "--format", tt.format})
			err = root.Execute()
			if tt.whoisFails {
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("unexpected error: %v", err)
				}
			} else if err != nil || !strings.Contains(out.String(), tt.want) {
				t.Fatalf("unexpected result: %v %s", err, out.String())
			}
			wantWhois := 0
			if tt.rdapFails {
				wantWhois = 1
			}
			if rdapCalls != 1 || whoisCalls != wantWhois {
				t.Fatalf("incorrect queries: RDAP=%d WHOIS=%d", rdapCalls, whoisCalls)
			}
		})
	}
}

func TestDomainCancellationStopsFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root := NewRootCommand()
	old, _, err := root.Find([]string{"domain"})
	if err != nil {
		t.Fatal(err)
	}
	root.RemoveCommand(old)
	root.AddCommand(newDomainCommand(
		func(context.Context, string, time.Duration) (*rdap.Response, error) {
			cancel()
			return nil, context.Canceled
		},
		func(context.Context, string, time.Duration) (string, error) {
			t.Error("WHOIS fallback after cancellation")
			return "", nil
		},
	))
	root.SetArgs([]string{"domain", "example.com"})
	if err := root.ExecuteContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
