package cmd

import (
	"context"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	"watchr/internal/output"
	tlsinfo "watchr/internal/tls"
)

func NewTLSCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tls <host>",
		Short: "Retrieve TLS certificate chain information",
		Long: `Retrieve and display TLS certificate chain information for a host.

The command connects to the specified host and retrieves the TLS certificate
chain, showing details such as subject, issuer, validity dates, and more.

Use --scan-protocols to test which TLS versions are supported.
Use --scan-ciphers to enumerate supported cipher suites for each TLS version.
Use --full-scan to perform a comprehensive security scan including protocol
versions, cipher suites, and vulnerability detection.`,
		Args: cobra.ExactArgs(1),
		RunE: runTLS,
	}

	cmd.Flags().StringP("port", "p", "443", "Port to connect to")
	cmd.Flags().Bool("scan-protocols", false, "Scan for supported TLS protocol versions")
	cmd.Flags().Bool("scan-ciphers", false, "Enumerate supported cipher suites (implies --scan-protocols)")
	cmd.Flags().Bool("full-scan", false, "Perform full security scan (protocols, ciphers, vulnerabilities)")

	return cmd
}

func runTLS(cmd *cobra.Command, args []string) error {
	host := args[0]
	timeoutSecs, _ := cmd.Flags().GetInt("timeout")
	timeout := time.Duration(timeoutSecs) * time.Second
	format, _ := cmd.Flags().GetString("format")
	port, _ := cmd.Flags().GetString("port")
	fullScan, _ := cmd.Flags().GetBool("full-scan")
	scanCiphers, _ := cmd.Flags().GetBool("scan-ciphers")
	scanProtocols, _ := cmd.Flags().GetBool("scan-protocols")

	ctx := context.Background()
	formatter := output.NewFormatter(format, cmd.OutOrStdout())

	if fullScan || scanCiphers || scanProtocols {
		return runTLSScan(ctx, host, port, timeout, formatter, fullScan, scanCiphers)
	}

	tlsClient := tlsinfo.NewClient(timeout)

	slog.Info("retrieving TLS certificate", "host", host, "port", port, "timeout", timeout)

	resp, err := tlsClient.Fetch(ctx, host, port)
	if err != nil {
		return err
	}

	return formatter.OutputTLS(resp)
}

func runTLSScan(ctx context.Context, host, port string, timeout time.Duration, formatter *output.Formatter, fullScan, scanCiphers bool) error {
	scanner := tlsinfo.NewScanner(timeout)

	if fullScan {
		slog.Info("performing full TLS scan", "host", host, "port", port, "timeout", timeout)
		result, err := scanner.FullTest(ctx, host, port, true)
		if err != nil {
			return err
		}
		return formatter.OutputTLSScan(result)
	}

	if scanCiphers {
		slog.Info("scanning TLS cipher suites", "host", host, "port", port, "timeout", timeout)
		result, err := scanner.FullTest(ctx, host, port, true)
		if err != nil {
			return err
		}
		return formatter.OutputTLSScan(result)
	}

	slog.Info("scanning TLS protocol versions", "host", host, "port", port, "timeout", timeout)
	result, err := scanner.TestVersions(ctx, host, port)
	if err != nil {
		return err
	}
	return formatter.OutputTLSScan(result)
}

func init() {
	AddCommand(NewTLSCommand())
}
