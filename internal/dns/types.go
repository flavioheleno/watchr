package dns

import (
	"time"
)

type Response struct {
	Domain     string        `json:"domain"`
	RecordType string        `json:"recordType"`
	Nameserver string        `json:"nameserver"`
	QueryTime  time.Duration `json:"queryTime"`
	Records    []Record      `json:"records"`
}

type Record struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}
