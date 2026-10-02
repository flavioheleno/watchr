package cmd

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTLSCommandLocalServer(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		flags []string
		want  string
	}{
		{nil, "Certificate Chain"},
		{[]string{"--format", "json"}, "\"certificates\":"},
		{[]string{"--scan-protocols"}, "TLS 1.2: Yes"},
		{[]string{"--scan-ciphers"}, "Supported Cipher Suites"},
		{[]string{"--full-scan"}, "Scan Limitations:"},
	} {
		out, err := executeTestCommand(append([]string{"tls", host, "--port", port}, tt.flags...))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, tt.want) {
			t.Fatalf("missing %q in %s", tt.want, out)
		}
	}
}
