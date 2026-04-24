// Package main is the entry point for the Trusted-DNS Docker node.
// It initializes all components, performs bootstrap with the Worker,
// and starts the DNS listener on port 53/UDP.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
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
	trans := transport.New(config.WorkerURL, config.ProtocolPath, sess, keys)

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

	// refreshInProgress is an atomic flag to prevent concurrent refresh operations
	var refreshInProgress atomic.Bool

	// DNS query handler
	handler := func(ctx context.Context, query []byte) ([]byte, error) {
		// Auto-recover if bundle is missing (cleared due to error)
		if !sess.HasBundle() {
			// Check if re-bootstrap countdown has been triggered
			if !sess.ShouldRebootstrap() {
				// Trigger countdown if not already
				sess.TriggerRebootstrap()
				return nil, fmt.Errorf("re-bootstrap countdown in progress")
			}

			// Countdown elapsed, but double-check if bundle was set by another goroutine
			if sess.HasBundle() {
				log.Println("[main] bundle already set by another goroutine, skipping re-bootstrap")
				sess.CancelRebootstrap()
			} else {
				// Still no bundle, perform re-bootstrap
				log.Println("[main] starting re-bootstrap after countdown...")
				bundle, err := trans.Bootstrap(ctx)
				if err != nil {
					// Re-trigger countdown for next attempt
					sess.TriggerRebootstrap()
					return nil, fmt.Errorf("re-bootstrap failed: %w", err)
				}
				if err := sess.SetBundle(bundle); err != nil {
					return nil, fmt.Errorf("set bundle failed: %w", err)
				}
				log.Printf("[main] re-bootstrap complete: gen=%d", bundle.BundleGen)
			}
		}

		// Check if refresh is needed
		if sess.NeedsRefresh() {
			// Use atomic CompareAndSwap to ensure only one refresh goroutine runs at a time
			if refreshInProgress.CompareAndSwap(false, true) {
				go func() {
					defer refreshInProgress.Store(false)
					newBundle, err := trans.Refresh(context.Background())
					if err != nil {
						// Check if session is invalid
						var protoErr *protocol.ErrorResponse
						if errors.As(err, &protoErr) && protoErr.NeedsRebootstrap() {
							log.Printf("[main] refresh failed with session error, clearing bundle for re-bootstrap")
							sess.ClearBundle()
						} else {
							log.Printf("[main] refresh failed: %v", err)
						}
						return
					}
					if err := sess.SetBundle(newBundle); err != nil {
						log.Printf("[main] set new bundle failed: %v", err)
					}
				}()
			}
		}

		// Send query through Worker
		resp, err := trans.Query(ctx, query)
		if err != nil {
			// Check if error requires re-bootstrap
			var protoErr *protocol.ErrorResponse
			if errors.As(err, &protoErr) && protoErr.NeedsRebootstrap() {
				log.Printf("[main] fatal session error (%s), clearing bundle for re-bootstrap", protoErr)
				sess.ClearBundle()
				return nil, fmt.Errorf("session error: %w", protoErr)
			}
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
			// Auto-recover if bundle was cleared
			if !sess.HasBundle() {
				// Check if countdown is in progress or should trigger
				if sess.ShouldRebootstrap() {
					// Countdown elapsed, but double-check if bundle was set by another goroutine
					if sess.HasBundle() {
						log.Println("[main] bundle already set by another goroutine, skipping proactive re-bootstrap")
						sess.CancelRebootstrap()
						continue
					}

					// Still no bundle, perform re-bootstrap
					log.Println("[main] proactive re-bootstrap triggered (no bundle, countdown elapsed)")
					bundle, err := trans.Bootstrap(ctx)
					if err != nil {
						consecutiveFailures++
						log.Printf("[main] proactive re-bootstrap failed (attempt %d/%d): %v",
							consecutiveFailures, maxConsecutiveFailures, err)
						if consecutiveFailures >= maxConsecutiveFailures {
							log.Printf("[main] FATAL: re-bootstrap failed %d consecutive times, initiating container restart...",
								maxConsecutiveFailures)
							os.Exit(1)
						}
						// Re-trigger countdown for next attempt
						sess.TriggerRebootstrap()
						continue
					}
					if err := sess.SetBundle(bundle); err != nil {
						log.Printf("[main] set bundle failed: %v", err)
						continue
					}
					consecutiveFailures = 0
					log.Printf("[main] proactive re-bootstrap complete: gen=%d", bundle.BundleGen)
					continue
				} else {
					// Trigger or continue countdown
					sess.TriggerRebootstrap()
					continue
				}
			}

			if sess.NeedsRefresh() {
				log.Println("[main] proactive refresh triggered")
				newBundle, err := trans.Refresh(ctx)
				if err != nil {
					// Check if session is invalid
					var protoErr *protocol.ErrorResponse
					if errors.As(err, &protoErr) && protoErr.NeedsRebootstrap() {
						log.Printf("[main] refresh failed with session error, clearing bundle for re-bootstrap")
						sess.ClearBundle()
						// IMPORTANT: Count this as a failure - worker may be having issues
						consecutiveFailures++
						log.Printf("[main] session error (attempt %d/%d): %v",
							consecutiveFailures, maxConsecutiveFailures, protoErr)
						if consecutiveFailures >= maxConsecutiveFailures {
							log.Printf("[main] FATAL: session errors %d consecutive times, initiating container restart...",
								maxConsecutiveFailures)
							os.Exit(1)
						}
						continue
					}

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
	ProtocolPath     string
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

	protocolPath := os.Getenv("PROTOCOL_PATH")
	if protocolPath == "" {
		protocolPath = "/dns-query"
	}

	return &Config{
		WorkerURL:    workerURL,
		ProtocolPath: protocolPath,
		RootSeed:     rootSeed,
		ListenAddr:   listenAddr,
		ProbeMode:    probeMode,
	}, nil
}
