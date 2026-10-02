package cmd

import (
	"context"
	"errors"
	"io"
	"testing"
)

func TestCanceledCommands(t *testing.T) {
	for _, args := range [][]string{
		{"domain", ""},
		{"http", "http://127.0.0.1:1"},
		{"dns", "example.com", "--server", "127.0.0.1:1"},
		{"tls", "127.0.0.1", "--port", "invalid"},
		{"tls", "127.0.0.1", "--port", "invalid", "--scan-protocols"},
	} {
		t.Run(args[0], func(t *testing.T) {
			rootCmd := NewRootCommand()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			rootCmd.SetOut(io.Discard)
			rootCmd.SetErr(io.Discard)
			rootCmd.SetArgs(args)
			if err := rootCmd.ExecuteContext(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("expected cancellation, got %v", err)
			}
		})
	}
}
