package cmd

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var (
	format  string
	timeout int
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "watchr",
	Short: "watchr - retrieve domain, TLS, and HTTP information",
	Long: `watchr is a CLI tool to retrieve:
  - Domain registration details (RDAP/WHOIS)
  - TLS certificate chain information
  - HTTP response details`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
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

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&format, "format", "f", "text", "Output format (text|json)")
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 10, "Request timeout in seconds")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
}

func GetFormat() string {
	return format
}

func GetTimeout() int {
	return timeout
}

func AddCommand(cmd *cobra.Command) {
	rootCmd.AddCommand(cmd)
}
