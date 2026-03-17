// Secretr - Military-grade secrets management platform
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/oarkflow/velocity/internal/secretr/cli/app"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	// Initialize app with velocity integration
	cliApp, err := app.NewApp(nil)
	if err != nil {
		return fmt.Errorf("failed to initialize app: %w", err)
	}
	defer cliApp.Close()

	return cliApp.Run(ctx, os.Args)
}
