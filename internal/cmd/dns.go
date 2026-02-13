package cmd

import (
	"context"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	dnsinfo "watchr/internal/dns"
	"watchr/internal/output"
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

	cmd.Flags().StringP("type", "T", "A", "Record type (A, AAAA, MX, NS, CNAME, TXT, SOA, SRV, PTR, CAA)")
	cmd.Flags().StringP("server", "s", "", "DNS server to query (default: system resolver, port defaults to 53)")

	return cmd
}

func runDNS(cmd *cobra.Command, args []string) error {
	domain := args[0]
	timeoutSecs, _ := cmd.Flags().GetInt("timeout")
	timeout := time.Duration(timeoutSecs) * time.Second
	format, _ := cmd.Flags().GetString("format")
	recordType, _ := cmd.Flags().GetString("type")
	server, _ := cmd.Flags().GetString("server")

	ctx := context.Background()

	dnsClient := dnsinfo.NewClient(timeout, server)
	formatter := output.NewFormatter(format, cmd.OutOrStdout())

	slog.Info("querying DNS", "domain", domain, "type", recordType, "server", server, "timeout", timeout)

	resp, err := dnsClient.Query(ctx, domain, recordType)
	if err != nil {
		return err
	}

	return formatter.OutputDNS(resp)
}

func init() {
	AddCommand(NewDNSCommand())
}
