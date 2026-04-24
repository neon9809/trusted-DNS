// Package main is the entry point for the Trusted-DNS Docker node.
// It initializes all components, performs bootstrap with the Worker,
// and starts the DNS listener on port 53/UDP.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/neon9809/trusted-dns/docker/internal/listener"
	"github.com/neon9809/trusted-dns/docker/internal/probe"
	"github.com/neon9809/trusted-dns/docker/internal/protocol"
	"github.com/neon9809/trusted-dns/docker/internal/rewriter"
	"github.com/neon9809/trusted-dns/docker/internal/session"
	"github.com/neon9809/trusted-dns/docker/internal/transport"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("[main] Trusted-DNS Docker node starting...")

	// Load configuration from environment
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("[main] configuration error: %v", err)
	}

	// Derive keys from root seed
	rootSeed, err := protocol.HexToBytes(config.RootSeed)
	if err != nil {
		log.Fatalf("[main] invalid ROOT_SEED: %v", err)
	}

	keys, err := protocol.DeriveAllKeys(rootSeed)
	if err != nil {
		log.Fatalf("[main] key derivation failed: %v", err)
	}

	clientID, err := protocol.DeriveClientID(rootSeed)
	if err != nil {
		log.Fatalf("[main] client ID derivation failed: %v", err)
	}

	log.Printf("[main] client_id_prefix: %s", protocol.BytesToHex(clientID[:8]))

	// Initialize session manager
	sess := session.New(keys, clientID)

	// Initialize transport
	trans := transport.New(config.WorkerURL, sess, keys)

	// Bootstrap
	ctx := context.Background()
	bundle, err := trans.Bootstrap(ctx)
	if err != nil {
		log.Fatalf("[main] bootstrap failed: %v", err)
	}

	if err := sess.SetBundle(bundle); err != nil {
		log.Fatalf("[main] set bundle failed: %v", err)
	}

	// Initialize probe engine
	probeConfig := probe.Config{
		Mode:      probe.Mode(config.ProbeMode),
		Timeout:   2 * time.Second,
		MaxProbes: 8,
	}
	probeEngine := probe.New(probeConfig)

	// Initialize rewriter
	rewriterConfig := rewriter.Config{
		Enabled:    true,
		MinTTL:     60,
		SingleAddr: false,
	}
	rw := rewriter.New(rewriterConfig, probeEngine)

	// DNS query handler
	handler := func(ctx context.Context, query []byte) ([]byte, error) {
		// Check if refresh is needed
		if sess.NeedsRefresh() {
			go func() {
				newBundle, err := trans.Refresh(context.Background())
				if err != nil {
					log.Printf("[main] refresh failed: %v", err)
					return
				}
				if err := sess.SetBundle(newBundle); err != nil {
					log.Printf("[main] set new bundle failed: %v", err)
				}
			}()
		}

		// Send query through Worker
		resp, err := trans.Query(ctx, query)
		if err != nil {
			return nil, fmt.Errorf("query via worker: %w", err)
		}

		// Rewrite response (probe + reorder)
		resp = rw.Rewrite(ctx, query, resp)

		return resp, nil
	}

	// Start DNS listener
	listenAddr := config.ListenAddr
	dnsListener := listener.New(listenAddr, handler)
	if err := dnsListener.Start(); err != nil {
		log.Fatalf("[main] listener start failed: %v", err)
	}

	log.Printf("[main] Trusted-DNS Docker node ready (worker=%s, listen=%s)",
		config.WorkerURL, listenAddr)

	// Start background refresh ticker
	go refreshLoop(ctx, sess, trans)

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("[main] received signal %s, shutting down...", sig)

	dnsListener.Stop()
	log.Println("[main] Trusted-DNS Docker node stopped")
}

// refreshLoop periodically checks if the bundle needs refreshing.
// If refresh fails more than 5 consecutive times, the process exits to restart the container.
func refreshLoop(ctx context.Context, sess *session.Manager, trans *transport.Transport) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	var consecutiveFailures int
	const maxConsecutiveFailures = 5

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if sess.NeedsRefresh() {
				log.Println("[main] proactive refresh triggered")
				newBundle, err := trans.Refresh(ctx)
				if err != nil {
					consecutiveFailures++
					log.Printf("[main] proactive refresh failed (attempt %d/%d): %v",
						consecutiveFailures, maxConsecutiveFailures, err)

					if consecutiveFailures >= maxConsecutiveFailures {
						log.Printf("[main] FATAL: refresh failed %d consecutive times, initiating container restart...",
							maxConsecutiveFailures)
						os.Exit(1)
					}
					continue
				}

				// Refresh succeeded, reset failure counter
				if consecutiveFailures > 0 {
					log.Printf("[main] refresh succeeded, resetting failure counter from %d", consecutiveFailures)
					consecutiveFailures = 0
				}

				if err := sess.SetBundle(newBundle); err != nil {
					log.Printf("[main] set refreshed bundle failed: %v", err)
				}
			}
		}
	}
}

// Config holds the application configuration.
type Config struct {
	WorkerURL        string
	RootSeed         string
	ListenAddr       string
	ProbeMode        string
	TicketsPerBundle int
	QueriesPerBundle int
}

func loadConfig() (*Config, error) {
	workerURL := os.Getenv("WORKER_URL")
	if workerURL == "" {
		return nil, fmt.Errorf("WORKER_URL is required")
	}
	// Ensure no trailing slash
	workerURL = strings.TrimRight(workerURL, "/")

	rootSeed := os.Getenv("ROOT_SEED")
	if rootSeed == "" {
		return nil, fmt.Errorf("ROOT_SEED is required")
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = "0.0.0.0:53"
	}

	probeMode := os.Getenv("PROBE_MODE")
	if probeMode == "" {
		probeMode = "tcp443"
	}

	return &Config{
		WorkerURL:  workerURL,
		RootSeed:   rootSeed,
		ListenAddr: listenAddr,
		ProbeMode:  probeMode,
	}, nil
}
