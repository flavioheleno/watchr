package httpinfo

import (
	"crypto/tls"
	"net/http/httptrace"
	"sync"
	"time"
)

type requestTimings struct {
	mu            sync.Mutex
	dnsStart      time.Time
	connectStarts map[string]time.Time
	tlsStart      time.Time
	wroteRequest  time.Time
	timings       Timings
}

func (r *requestTimings) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.dnsStart = time.Now()
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			r.mu.Lock()
			defer r.mu.Unlock()
			if !r.dnsStart.IsZero() {
				r.timings.DNSLookup += time.Since(r.dnsStart)
				r.dnsStart = time.Time{}
			}
		},
		ConnectStart: func(network, address string) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.connectStarts[network+" "+address] = time.Now()
		},
		ConnectDone: func(network, address string, err error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			key := network + " " + address
			if start, ok := r.connectStarts[key]; ok && err == nil {
				r.timings.TCPConnection += time.Since(start)
			}
			delete(r.connectStarts, key)
		},
		TLSHandshakeStart: func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.tlsStart = time.Now()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			if !r.tlsStart.IsZero() && err == nil {
				r.timings.TLSHandshake += time.Since(r.tlsStart)
			}
			r.tlsStart = time.Time{}
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			r.mu.Lock()
			defer r.mu.Unlock()
			if info.Err == nil {
				r.wroteRequest = time.Now()
			}
		},
		GotFirstResponseByte: func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			if !r.wroteRequest.IsZero() {
				r.timings.ServerProcessing += time.Since(r.wroteRequest)
				r.wroteRequest = time.Time{}
			}
		},
	}
}

func (r *requestTimings) snapshot() Timings {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.timings
}
