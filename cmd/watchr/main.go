package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"watchr/internal/cmd"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cmd.NewRootCommand().ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
