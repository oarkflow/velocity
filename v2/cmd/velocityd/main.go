// Command velocityd is the Velocity v2 server entrypoint. It reads a JSON
// plugin manifest, boots the microkernel with whichever plugins the
// manifest enables, and runs until SIGINT/SIGTERM triggers a graceful
// shutdown. See v2/docs/ARCHITECTURE.md for the plugin/microkernel model
// this drives.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oarkflow/velocity/v2/internal/bootstrap"
	"github.com/oarkflow/velocity/v2/kernel"
)

func main() {
	manifestPath := flag.String("manifest", "config/velocityd.example.bcl", "path to the plugin manifest BCL file")
	shutdownTimeout := flag.Duration("shutdown-timeout", 15*time.Second, "grace period for shutdown before forcing exit")
	watchManifest := flag.Bool("watch-manifest", false, "poll the manifest file for changes and hot-reload the kernel when it's edited (also reloads on SIGHUP on non-Windows platforms) — see kernel.Reload's doc comment for exactly what a reload does and refuses")
	watchInterval := flag.Duration("watch-interval", 2*time.Second, "how often to check the manifest file's mtime when -watch-manifest is set")
	flag.Parse()

	if err := run(*manifestPath, *shutdownTimeout, *watchManifest, *watchInterval); err != nil {
		fmt.Fprintln(os.Stderr, "velocityd:", err)
		os.Exit(1)
	}
}

func run(manifestPath string, shutdownTimeout time.Duration, watchManifest bool, watchInterval time.Duration) error {
	manifest, err := kernel.LoadManifestBCL(manifestPath)
	if err != nil {
		return fmt.Errorf("loading manifest %q: %w", manifestPath, err)
	}

	k := kernel.New(manifest)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := k.Boot(ctx, bootstrap.AllPlugins(manifest), manifest.Enabled()); err != nil {
		return fmt.Errorf("booting kernel: %w", err)
	}
	logHealth(k)

	if watchManifest {
		absPath := manifestPath
		go kernel.WatchManifestWithSignal(ctx, absPath, watchInterval, func(newManifest kernel.Manifest) error {
			log.Println("velocityd: manifest change detected, reloading...")
			if err := k.Reload(context.Background(), newManifest, bootstrap.AllPlugins(newManifest)); err != nil {
				log.Println("velocityd: reload failed, previous configuration still running:", err)
				return err
			}
			log.Println("velocityd: reload applied successfully")
			logHealth(k)
			return nil
		})
		log.Printf("velocityd: watching %q for changes every %s (SIGHUP also triggers a reload on non-Windows)", manifestPath, watchInterval)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("velocityd: shutdown signal received, stopping plugins...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	if err := k.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutting down: %w", err)
	}
	log.Println("velocityd: stopped cleanly")
	return nil
}

func logHealth(k *kernel.Kernel) {
	h := k.Health()
	log.Printf("velocityd: booted, %d plugin(s) running", len(h))
	for name, health := range h {
		log.Printf("velocityd:   %-16s %-8s %s", name, health.Status, health.Detail)
	}
}
