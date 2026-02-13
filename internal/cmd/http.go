package cmd

import (
	"context"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	httpinfo "watchr/internal/http"
	"watchr/internal/output"
)

func NewHTTPCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "http <url>",
		Short: "Fetch HTTP response information",
		Long: `Fetch and display HTTP response information including status, headers,
response time, and TLS details (for HTTPS URLs).

By default, the command does not follow redirects. Use --follow-redirects
to enable automatic redirect following.

Use --timings to see a detailed breakdown of request timing including DNS lookup,
TCP connection, TLS handshake, server processing, and content transfer times.`,
		Args: cobra.ExactArgs(1),
		RunE: runHTTP,
	}

	cmd.Flags().BoolP("follow-redirects", "L", false, "Follow HTTP redirects")
	cmd.Flags().Bool("timings", false, "Show detailed timing breakdown")

	return cmd
}

func runHTTP(cmd *cobra.Command, args []string) error {
	url := args[0]
	timeoutSecs, _ := cmd.Flags().GetInt("timeout")
	timeout := time.Duration(timeoutSecs) * time.Second
	format, _ := cmd.Flags().GetString("format")
	followRedirects, _ := cmd.Flags().GetBool("follow-redirects")
	showTimings, _ := cmd.Flags().GetBool("timings")

	ctx := context.Background()

	httpClient := httpinfo.NewClient(timeout, followRedirects, showTimings)
	formatter := output.NewFormatter(format, cmd.OutOrStdout())

	slog.Info("fetching URL", "url", url, "timeout", timeout, "follow_redirects", followRedirects, "timings", showTimings)

	resp, err := httpClient.Fetch(ctx, url)
	if err != nil {
		return err
	}

	return formatter.OutputHTTP(resp)
}

func init() {
	AddCommand(NewHTTPCommand())
}
