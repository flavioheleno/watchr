package cmd

import (
	"net"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
)

func TestDNSCommandLocalServer(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{PacketConn: conn, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		msg := new(mdns.Msg)
		msg.SetReply(req)
		if req.Question[0].Qtype == mdns.TypeAAAA {
			msg.Answer = []mdns.RR{&mdns.AAAA{Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::1")}}
		} else {
			msg.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")}}
		}
		if err := w.WriteMsg(msg); err != nil {
			t.Error(err)
		}
	})}
	started := make(chan struct{})
	done := make(chan error, 1)
	server.NotifyStartedFunc = func() { close(started) }
	go func() { done <- server.ActivateAndServe() }()
	<-started
	defer func() {
		if err := server.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	for _, tt := range []struct{ recordType, format, want string }{
		{"A", "text", "192.0.2.1"}, {"AAAA", "json", "2001:db8::1"},
	} {
		out, err := executeTestCommand([]string{"dns", "example.com", "--server", conn.LocalAddr().String(), "--type", tt.recordType, "--format", tt.format})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, tt.want) || !strings.Contains(out, conn.LocalAddr().String()) {
			t.Fatalf("unexpected output: %s", out)
		}
	}
}
