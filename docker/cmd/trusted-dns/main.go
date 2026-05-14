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
	"strconv"
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

	// Create root context for background tasks
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	// Bootstrap
	bootCtx, bootCancel := context.WithTimeout(rootCtx, 30*time.Second)
	defer bootCancel()
	bundle, err := trans.Bootstrap(bootCtx)
	if err != nil {
		log.Fatalf("[main] bootstrap failed: %v", err)
	}

	if err := sess.SetBundle(bundle); err != nil {
		log.Fatalf("[main] set bundle failed: %v", err)
	}

	// Initialize probe engine
	probeConfig := probe.Config{
		Mode:      probe.Mode(config.ProbeMode),
		Budget:    config.ProbeBudget,
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
	var refreshFailures atomic.Int32
	const maxRefreshFailures = 5

	triggerRefresh := func(reason string) {
		if !refreshInProgress.CompareAndSwap(false, true) {
			log.Printf("[main] refresh already in progress, skipping %s trigger", reason)
			return
		}

		baseGen, ok := sess.GetBundleGen()
		if !ok {
			refreshInProgress.Store(false)
			log.Printf("[main] skipping %s refresh trigger: no active bundle", reason)
			return
		}

		go func(baseGen uint64, reason string) {
			defer refreshInProgress.Store(false)

			refreshCtx, cancel := context.WithTimeout(rootCtx, 30*time.Second)
			defer cancel()

			newBundle, err := trans.Refresh(refreshCtx)
			if err != nil {
				currentGen, hasBundle := sess.GetBundleGen()
				if !hasBundle || currentGen != baseGen {
					log.Printf("[main] stale %s refresh failure ignored for gen=%d", reason, baseGen)
					return
				}

				var protoErr *protocol.ErrorResponse
				if errors.As(err, &protoErr) && protoErr.NeedsRebootstrap() {
					if sess.ClearBundleIfGenMatches(baseGen) {
						log.Printf("[main] %s refresh failed with session error, cleared bundle gen=%d for re-bootstrap", reason, baseGen)
					} else {
						log.Printf("[main] stale %s refresh session error ignored for gen=%d", reason, baseGen)
						return
					}
				} else {
					log.Printf("[main] %s refresh failed for gen=%d: %v", reason, baseGen, err)
				}

				failures := refreshFailures.Add(1)
				log.Printf("[main] refresh failure count %d/%d after %s trigger", failures, maxRefreshFailures, reason)
				if failures >= maxRefreshFailures {
					log.Printf("[main] FATAL: refresh failed %d consecutive times, initiating container restart...",
						maxRefreshFailures)
					os.Exit(1)
				}
				return
			}

			applied, err := sess.SetBundleIfGenMatches(baseGen, newBundle)
			if err != nil {
				failures := refreshFailures.Add(1)
				log.Printf("[main] set refreshed bundle failed after %s trigger (gen=%d): %v", reason, baseGen, err)
				if failures >= maxRefreshFailures {
					log.Printf("[main] FATAL: refresh apply failed %d consecutive times, initiating container restart...",
						maxRefreshFailures)
					os.Exit(1)
				}
				return
			}
			if !applied {
				log.Printf("[main] stale %s refresh result ignored for gen=%d", reason, baseGen)
				return
			}

			log.Printf("[main] %s refresh complete: gen=%d -> gen=%d", reason, baseGen, newBundle.BundleGen)

			if failures := refreshFailures.Swap(0); failures > 0 {
				log.Printf("[main] refresh succeeded after %d consecutive failures", failures)
			}
		}(baseGen, reason)
	}

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
				rebootCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				bundle, err := trans.Bootstrap(rebootCtx)
				cancel()
				if err != nil {
					// Re-trigger countdown for next attempt
					sess.TriggerRebootstrap()
					return nil, fmt.Errorf("re-bootstrap failed: %w", err)
				}
				if err := sess.SetBundle(bundle); err != nil {
					return nil, fmt.Errorf("set bundle failed: %w", err)
				}
				refreshFailures.Store(0)
				log.Printf("[main] re-bootstrap complete: gen=%d", bundle.BundleGen)
			}
		}

		// Check if refresh is needed
		if sess.NeedsRefresh() {
			triggerRefresh("query-hot-path")
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
	go refreshLoop(rootCtx, sess, trans, triggerRefresh, func() {
		refreshFailures.Store(0)
	})

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("[main] received signal %s, shutting down...", sig)

	dnsListener.Stop()
	log.Println("[main] Trusted-DNS Docker node stopped")
}

// refreshLoop periodically checks if the bundle needs refreshing and proactively
// re-bootstraps when the active bundle has been cleared.
func refreshLoop(
	ctx context.Context,
	sess *session.Manager,
	trans *transport.Transport,
	triggerRefresh func(reason string),
	resetRefreshFailures func(),
) {
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
					rebootCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
					bundle, err := trans.Bootstrap(rebootCtx)
					cancel()
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
					resetRefreshFailures()
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
				triggerRefresh("refresh-loop")
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
	ProbeBudget      time.Duration
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

	probeBudget := 50 * time.Millisecond
	if rawProbeBudget := os.Getenv("PROBE_BUDGET_MS"); rawProbeBudget != "" {
		parsedProbeBudget, err := strconv.Atoi(rawProbeBudget)
		if err != nil || parsedProbeBudget < 0 {
			return nil, fmt.Errorf("PROBE_BUDGET_MS must be a non-negative integer")
		}
		probeBudget = time.Duration(parsedProbeBudget) * time.Millisecond
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
		ProbeBudget:  probeBudget,
	}, nil
}
