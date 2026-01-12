package httpinfo

import (
	"time"
)

type Timings struct {
	DNSLookup        time.Duration `json:"dnsLookup"`
	TCPConnection    time.Duration `json:"tcpConnection"`
	TLSHandshake     time.Duration `json:"tlsHandshake"`
	ServerProcessing time.Duration `json:"serverProcessing"`
	ContentTransfer  time.Duration `json:"contentTransfer"`
	Total            time.Duration `json:"total"`
}

type Response struct {
	URL              string            `json:"url"`
	StatusCode       int               `json:"statusCode"`
	Status           string            `json:"status"`
	Headers          map[string]string `json:"headers"`
	ContentLength    int64             `json:"contentLength"`
	TransferEncoding []string          `json:"transferEncoding,omitempty"`
	Duration         time.Duration     `json:"duration"`
	Timings          *Timings          `json:"timings,omitempty"`
	TLSVersion       string            `json:"tlsVersion,omitempty"`
	TLSCipherSuite   string            `json:"tlsCipherSuite,omitempty"`
	RedirectChain    []string          `json:"redirectChain,omitempty"`
}
