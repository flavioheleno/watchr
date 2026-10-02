package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	"github.com/flavioheleno/watchr/internal/output"
	"github.com/flavioheleno/watchr/internal/rdap"
	"github.com/flavioheleno/watchr/internal/whois"
)

func NewDomainCommand() *cobra.Command {
	return newDomainCommand(
		func(ctx context.Context, domain string, timeout time.Duration) (*rdap.Response, error) {
			return rdap.NewClient(timeout).QueryDomain(ctx, domain)
		},
		func(ctx context.Context, domain string, timeout time.Duration) (string, error) {
			return whois.NewClient(timeout).Query(ctx, domain)
		},
	)
}

type rdapQuery func(context.Context, string, time.Duration) (*rdap.Response, error)
type whoisQuery func(context.Context, string, time.Duration) (string, error)

func newDomainCommand(queryRDAP rdapQuery, queryWHOIS whoisQuery) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "domain <domain-name>",
		Short: "Query domain registration information",
		Long: `Query domain registration information using RDAP with WHOIS fallback.

The command first attempts to query the domain using RDAP (Registration Data
Access Protocol). If RDAP is unavailable or fails, it falls back to WHOIS.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDomain(cmd, args, queryRDAP, queryWHOIS)
		},
	}

	return cmd
}

func runDomain(cmd *cobra.Command, args []string, queryRDAP rdapQuery, queryWHOIS whoisQuery) error {
	domain := args[0]
	timeoutSecs, _ := cmd.Flags().GetInt("timeout")
	timeout := time.Duration(timeoutSecs) * time.Second
	format, _ := cmd.Flags().GetString("format")

	ctx := cmd.Context()
	if err := ctx.Err(); err != nil {
		return err
	}

	formatter := output.NewFormatter(format, cmd.OutOrStdout())

	slog.Info("querying domain", "domain", domain, "timeout", timeout)

	rdapResp, rdapErr := queryRDAP(ctx, domain, timeout)
	if rdapErr == nil {
		return formatter.OutputRDAP(rdapResp)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	slog.Debug("RDAP query failed, falling back to WHOIS", "error", rdapErr)

	whoisResp, whoisErr := queryWHOIS(ctx, domain, timeout)
	if whoisErr != nil {
		return fmt.Errorf("both RDAP and WHOIS queries failed: %w", fmt.Errorf("RDAP: %w; WHOIS: %w", rdapErr, whoisErr))
	}

	return formatter.OutputWHOIS(whoisResp)
}
