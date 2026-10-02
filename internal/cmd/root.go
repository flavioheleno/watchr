package cmd

import (
	"fmt"
	"log/slog"
	"math"
	"os"
	"time"

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
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			format, err := cmd.Flags().GetString("format")
			if err != nil {
				return err
			}
			if format != "text" && format != "json" {
				return fmt.Errorf("unsupported output format %q: use text or json", format)
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				return err
			}
			maxTimeout := int64(math.MaxInt64) / int64(time.Second)
			if timeout <= 0 || int64(timeout) > maxTimeout {
				return fmt.Errorf("timeout must be positive and no greater than %d seconds", maxTimeout)
			}
			verbose, err := cmd.Flags().GetBool("verbose")
			if err != nil {
				return err
			}
			level := slog.LevelInfo
			if verbose {
				level = slog.LevelDebug
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: level,
			}))
			slog.SetDefault(logger)
			return nil
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
