package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	"watchr/internal/output"
	"watchr/internal/rdap"
	"watchr/internal/whois"
)

func NewDomainCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "domain <domain-name>",
		Short: "Query domain registration information",
		Long: `Query domain registration information using RDAP with WHOIS fallback.

The command first attempts to query the domain using RDAP (Registration Data
Access Protocol). If RDAP is unavailable or fails, it falls back to WHOIS.`,
		Args: cobra.ExactArgs(1),
		RunE: runDomain,
	}

	return cmd
}

func runDomain(cmd *cobra.Command, args []string) error {
	domain := args[0]
	timeoutSecs, _ := cmd.Flags().GetInt("timeout")
	timeout := time.Duration(timeoutSecs) * time.Second
	format, _ := cmd.Flags().GetString("format")

	ctx := context.Background()

	rdapClient := rdap.NewClient(timeout)
	whoisClient := whois.NewClient(timeout)
	formatter := output.NewFormatter(format, cmd.OutOrStdout())

	slog.Info("querying domain", "domain", domain, "timeout", timeout)

	rdapResp, rdapErr := rdapClient.QueryDomain(ctx, domain)
	if rdapErr == nil {
		return formatter.OutputRDAP(rdapResp)
	}

	slog.Debug("RDAP query failed, falling back to WHOIS", "error", rdapErr)

	whoisResp, whoisErr := whoisClient.Query(ctx, domain)
	if whoisErr != nil {
		return fmt.Errorf("both RDAP and WHOIS queries failed: %w", fmt.Errorf("RDAP: %w; WHOIS: %w", rdapErr, whoisErr))
	}

	return formatter.OutputWHOIS(whoisResp)
}

func init() {
	AddCommand(NewDomainCommand())
}
