package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

type Client struct {
	timeout    time.Duration
	nameserver string
}

func NewClient(timeout time.Duration, nameserver string) *Client {
	if nameserver == "" {
		nameserver = getSystemDNS()
	}

	nameserver = ensurePort(nameserver)

	return &Client{
		timeout:    timeout,
		nameserver: nameserver,
	}
}

func getSystemDNS() string {
	config, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(config.Servers) == 0 {
		slog.Debug("failed to read system DNS, using default", "error", err)
		return "8.8.8.8"
	}
	return config.Servers[0]
}

func ensurePort(nameserver string) string {
	if strings.Contains(nameserver, ":") {
		return nameserver
	}

	if net.ParseIP(nameserver) != nil {
		return net.JoinHostPort(nameserver, "53")
	}

	return nameserver
}

func (c *Client) Query(ctx context.Context, domain string, recordType string) (*Response, error) {
	domain = mdns.Fqdn(domain)

	qtype, err := parseRecordType(recordType)
	if err != nil {
		return nil, err
	}

	m := new(mdns.Msg)
	m.SetQuestion(domain, qtype)
	m.RecursionDesired = true

	client := &mdns.Client{
		Timeout: c.timeout,
	}

	slog.Debug("querying DNS", "domain", domain, "type", recordType, "nameserver", c.nameserver)
	start := time.Now()
	r, _, err := client.ExchangeContext(ctx, m, c.nameserver)
	queryTime := time.Since(start)

	if err != nil {
		return nil, err
	}

	if r.Rcode != mdns.RcodeSuccess {
		return &Response{
			Domain:     domain,
			RecordType: recordType,
			Nameserver: c.nameserver,
			QueryTime:  queryTime,
			Records:    []Record{},
		}, nil
	}

	response := &Response{
		Domain:     domain,
		RecordType: recordType,
		Nameserver: c.nameserver,
		QueryTime:  queryTime,
		Records:    make([]Record, 0),
	}

	for _, ans := range r.Answer {
		record := parseAnswer(ans)
		if record != nil {
			response.Records = append(response.Records, *record)
		}
	}

	return response, nil
}

func parseRecordType(recordType string) (uint16, error) {
	recordType = strings.ToUpper(recordType)

	types := map[string]uint16{
		"A":     mdns.TypeA,
		"AAAA":  mdns.TypeAAAA,
		"CNAME": mdns.TypeCNAME,
		"MX":    mdns.TypeMX,
		"NS":    mdns.TypeNS,
		"TXT":   mdns.TypeTXT,
		"SOA":   mdns.TypeSOA,
		"SRV":   mdns.TypeSRV,
		"PTR":   mdns.TypePTR,
		"CAA":   mdns.TypeCAA,
	}

	qtype, ok := types[recordType]
	if !ok {
		return 0, fmt.Errorf("unsupported record type: %s", recordType)
	}

	return qtype, nil
}

func parseAnswer(ans mdns.RR) *Record {
	header := ans.Header()

	record := &Record{
		Type: mdns.TypeToString[header.Rrtype],
		TTL:  header.Ttl,
	}

	switch rr := ans.(type) {
	case *mdns.A:
		record.Value = rr.A.String()
	case *mdns.AAAA:
		record.Value = rr.AAAA.String()
	case *mdns.CNAME:
		record.Value = rr.Target
	case *mdns.MX:
		record.Value = fmt.Sprintf("%d %s", rr.Preference, rr.Mx)
	case *mdns.NS:
		record.Value = rr.Ns
	case *mdns.TXT:
		record.Value = strings.Join(rr.Txt, " ")
	case *mdns.SOA:
		record.Value = fmt.Sprintf("%s %s %d %d %d %d %d",
			rr.Ns, rr.Mbox, rr.Serial, rr.Refresh, rr.Retry, rr.Expire, rr.Minttl)
	case *mdns.SRV:
		record.Value = fmt.Sprintf("%d %d %d %s",
			rr.Priority, rr.Weight, rr.Port, rr.Target)
	case *mdns.PTR:
		record.Value = rr.Ptr
	case *mdns.CAA:
		record.Value = fmt.Sprintf("%d %s %s",
			rr.Flag, rr.Tag, rr.Value)
	default:
		return nil
	}

	return record
}
