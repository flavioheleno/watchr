package cmd

import (
	"context"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	dnsinfo "watchr/internal/dns"
	"watchr/internal/output"
)

var (
	dnsRecordType string
	dnsServer     string
)

func NewDNSCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns <domain>",
		Short: "Perform DNS lookups",
		Long: `Query DNS records for a domain.

The command queries DNS records from the specified nameserver (default: system resolver).
Supports common record types including A, AAAA, MX, NS, CNAME, TXT, SOA, SRV, PTR, and CAA.`,
		Args: cobra.ExactArgs(1),
		RunE: runDNS,
	}

	cmd.Flags().StringVarP(&dnsRecordType, "type", "T", "A", "Record type (A, AAAA, MX, NS, CNAME, TXT, SOA, SRV, PTR, CAA)")
	cmd.Flags().StringVarP(&dnsServer, "server", "s", "", "DNS server to query (default: system resolver, port defaults to 53)")

	return cmd
}

func runDNS(cmd *cobra.Command, args []string) error {
	domain := args[0]
	timeout := time.Duration(GetTimeout()) * time.Second
	format := GetFormat()

	ctx := context.Background()

	dnsClient := dnsinfo.NewClient(timeout, dnsServer)
	formatter := output.NewFormatter(format, cmd.OutOrStdout())

	slog.Info("querying DNS", "domain", domain, "type", dnsRecordType, "server", dnsServer, "timeout", timeout)

	resp, err := dnsClient.Query(ctx, domain, dnsRecordType)
	if err != nil {
		return err
	}

	return formatter.OutputDNS(resp)
}

func init() {
	AddCommand(NewDNSCommand())
}
