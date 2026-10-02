package cmd

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "watchr",
		Short: "watchr - retrieve domain, TLS, and HTTP information",
		Long: `watchr is a CLI tool to retrieve:
  - Domain registration details (RDAP/WHOIS)
  - TLS certificate chain information
  - HTTP response details`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			verbose, _ := cmd.Flags().GetBool("verbose")
			level := slog.LevelInfo
			if verbose {
				level = slog.LevelDebug
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: level,
			}))
			slog.SetDefault(logger)
		},
	}
	rootCmd.PersistentFlags().StringP("format", "f", "text", "Output format (text|json)")
	rootCmd.PersistentFlags().IntP("timeout", "t", 10, "Request timeout in seconds")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose logging")
	rootCmd.AddCommand(NewDomainCommand(), NewHTTPCommand(), NewDNSCommand(), NewTLSCommand())
	return rootCmd
}

func Execute() error {
	return NewRootCommand().Execute()
}
