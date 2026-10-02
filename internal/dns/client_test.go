package dns

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func startDNSServer(t *testing.T, handler mdns.HandlerFunc) string {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	for _, server := range []*mdns.Server{{Listener: tcp, Handler: handler}, {PacketConn: udp, Handler: handler}} {
		started := make(chan struct{})
		done := make(chan error, 1)
		server.NotifyStartedFunc = func() { close(started) }
		go func() { done <- server.ActivateAndServe() }()
		<-started
		t.Cleanup(func() {
			if err := server.Shutdown(); err != nil {
				t.Error(err)
			}
			if err := <-done; err != nil {
				t.Error(err)
			}
		})
	}
	return tcp.Addr().String()
}

func TestClientQueryRecords(t *testing.T) {
	for _, tt := range []struct{ recordType, answer, value string }{
		{"A", "example.com. 60 IN A 192.0.2.1", "192.0.2.1"},
		{"AAAA", "example.com. 60 IN AAAA 2001:db8::1", "2001:db8::1"},
		{"MX", "example.com. 60 IN MX 10 mail.example.com.", "10 mail.example.com."},
		{"NS", "example.com. 60 IN NS ns.example.com.", "ns.example.com."},
		{"CNAME", "example.com. 60 IN CNAME target.example.com.", "target.example.com."},
		{"TXT", "example.com. 60 IN TXT \"abc\" \"def\"", "abcdef"},
		{"SOA", "example.com. 60 IN SOA ns.example.com. admin.example.com. 1 2 3 4 5", "ns.example.com. admin.example.com. 1 2 3 4 5"},
		{"SRV", "example.com. 60 IN SRV 1 2 443 target.example.com.", "1 2 443 target.example.com."},
		{"PTR", "example.com. 60 IN PTR target.example.com.", "target.example.com."},
		{"CAA", "example.com. 60 IN CAA 0 issue \"example.com\"", "0 issue example.com"},
	} {
		t.Run(tt.recordType, func(t *testing.T) {
			answer, err := mdns.NewRR(tt.answer)
			if err != nil {
				t.Fatal(err)
			}
			address := startDNSServer(t, func(w mdns.ResponseWriter, req *mdns.Msg) {
				msg := new(mdns.Msg)
				msg.SetReply(req)
				msg.Answer = []mdns.RR{answer}
				if err := w.WriteMsg(msg); err != nil {
					t.Error(err)
				}
			})
			resp, err := NewClient(time.Second, address).Query(context.Background(), "example.com", tt.recordType)
			if err != nil {
				t.Fatal(err)
			}
			want := []Record{{Type: tt.recordType, Value: tt.value, TTL: 60}}
			if !slices.Equal(resp.Records, want) {
				t.Fatalf("got %+v, want %+v", resp.Records, want)
			}
			if resp.Nameserver != address || resp.Domain != "example.com." || resp.QueryTime <= 0 {
				t.Fatalf("unexpected response: %+v", resp)
			}
		})
	}
}

func TestClientQueryResponseCodes(t *testing.T) {
	for _, code := range []int{mdns.RcodeSuccess, mdns.RcodeNameError, mdns.RcodeServerFailure, mdns.RcodeRefused} {
		t.Run(mdns.RcodeToString[code], func(t *testing.T) {
			address := startDNSServer(t, func(w mdns.ResponseWriter, req *mdns.Msg) {
				msg := new(mdns.Msg)
				msg.SetRcode(req, code)
				if err := w.WriteMsg(msg); err != nil {
					t.Error(err)
				}
			})
			resp, err := NewClient(time.Second, address).Query(context.Background(), "example.com", "A")
			if code == mdns.RcodeSuccess {
				if err != nil || resp == nil || len(resp.Records) != 0 {
					t.Fatalf("expected successful empty answer: %+v %v", resp, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), mdns.RcodeToString[code]) {
				t.Fatalf("response code lost: %+v %v", resp, err)
			}
		})
	}
}

func TestClientQueryRetriesTruncation(t *testing.T) {
	address := startDNSServer(t, func(w mdns.ResponseWriter, req *mdns.Msg) {
		msg := new(mdns.Msg)
		msg.SetReply(req)
		if w.RemoteAddr().Network() == "udp" {
			msg.Truncated = true
		} else {
			msg.Answer = []mdns.RR{&mdns.TXT{Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 60}, Txt: []string{strings.Repeat("x", 255), strings.Repeat("y", 255)}}}
		}
		if err := w.WriteMsg(msg); err != nil {
			t.Error(err)
		}
	})
	resp, err := NewClient(time.Second, address).Query(context.Background(), "example.com", "TXT")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Records) != 1 || len(resp.Records[0].Value) != 510 {
		t.Fatalf("incomplete answer: %+v", resp)
	}
}

func TestClientQueryRejectsTruncatedTCP(t *testing.T) {
	address := startDNSServer(t, func(w mdns.ResponseWriter, req *mdns.Msg) {
		msg := new(mdns.Msg)
		msg.SetReply(req)
		msg.Truncated = true
		if err := w.WriteMsg(msg); err != nil {
			t.Error(err)
		}
	})
	if _, err := NewClient(time.Second, address).Query(context.Background(), "example.com", "A"); err == nil {
		t.Fatal("expected error for truncated TCP response")
	}
}

func TestEnsurePort(t *testing.T) {
	for _, tt := range []struct{ input, want string }{
		{"8.8.8.8", "8.8.8.8:53"}, {"localhost", "localhost:53"},
		{"::1", "[::1]:53"}, {"[::1]", "[::1]:53"},
		{"fe80::1%eth0", "[fe80::1%eth0]:53"},
		{"[::1]:5353", "[::1]:5353"}, {"localhost:5353", "localhost:5353"},
	} {
		t.Run(tt.input, func(t *testing.T) {
			if got := ensurePort(tt.input); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClientQueryErrors(t *testing.T) {
	client := NewClient(time.Second, "127.0.0.1:53")
	if _, err := client.Query(context.Background(), "example.com", "INVALID"); err == nil {
		t.Fatal("expected record type error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Query(ctx, "example.com", "A"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	address := startDNSServer(t, func(mdns.ResponseWriter, *mdns.Msg) {})
	if _, err := NewClient(20*time.Millisecond, address).Query(context.Background(), "example.com", "A"); err == nil {
		t.Fatal("expected timeout")
	}
}
