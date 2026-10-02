package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPCommandLocalServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/redirect" {
			http.Redirect(w, req, "/final", http.StatusFound)
			return
		}
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		if _, err := w.Write([]byte("hello")); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	for _, tt := range []struct {
		flags      []string
		path, want string
	}{
		{nil, "/final", "Status: 200 OK"},
		{[]string{"--format", "json"}, "/final", "\"Set-Cookie\": ["},
		{[]string{"--timings"}, "/final", "Timing Breakdown:"},
		{nil, "/redirect", "Status Code: 302"},
		{[]string{"--follow-redirects"}, "/redirect", "Redirect Chain:"},
	} {
		out, err := executeTestCommand(append([]string{"http", server.URL + tt.path}, tt.flags...))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, tt.want) {
			t.Fatalf("missing %q in %s", tt.want, out)
		}
	}
}
