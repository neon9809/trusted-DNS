// Package probe implements the limited reachability probe engine
// for A/AAAA DNS records. It performs concurrent TCP probes
// to rank IP addresses by actual reachability and latency.
package probe

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Mode defines the probe mode.
type Mode string

const (
	ModeNone   Mode = "none"
	ModeTCP443 Mode = "tcp443"
	ModeICMP   Mode = "icmp"
	ModeBoth   Mode = "icmp,tcp443"
)

// Config holds probe engine configuration.
type Config struct {
	Mode      Mode
	Budget    time.Duration // total per-query budget; 0 waits for all probes
	Timeout   time.Duration
	MaxProbes int // max concurrent probes
}

// DefaultConfig returns the default probe configuration.
func DefaultConfig() Config {
	return Config{
		Mode:      ModeTCP443,
		Budget:    50 * time.Millisecond,
		Timeout:   2 * time.Second,
		MaxProbes: 8,
	}
}

// Result holds the probe result for a single IP address.
type Result struct {
	IP        net.IP
	RTT       time.Duration
	Reachable bool
}

// Engine performs reachability probes on IP addresses.
type Engine struct {
	config Config
}

// New creates a new probe engine.
func New(config Config) *Engine {
	return &Engine{config: config}
}

// ProbeAddresses probes a list of IP addresses and returns them
// sorted by reachability and latency (best first).
func (e *Engine) ProbeAddresses(ctx context.Context, ips []net.IP) []Result {
	if e.config.Mode == ModeNone || len(ips) == 0 {
		results := make([]Result, len(ips))
		for i, ip := range ips {
			results[i] = Result{IP: ip, Reachable: true, RTT: 0}
		}
		return results
	}

	maxProbes := e.config.MaxProbes
	if maxProbes <= 0 {
		maxProbes = 8
	}
	if len(ips) > maxProbes {
		ips = ips[:maxProbes]
	}

	if e.config.Budget > 0 {
		return e.probeAddressesWithBudget(ctx, ips, e.config.Budget)
	}

	results := make([]Result, len(ips))
	var wg sync.WaitGroup

	for i, ip := range ips {
		wg.Add(1)
		go func(idx int, addr net.IP) {
			defer wg.Done()
			results[idx] = e.probeOne(ctx, addr)
		}(i, ip)
	}

	wg.Wait()

	// Sort: reachable first, then by RTT
	sort.Slice(results, func(i, j int) bool {
		if results[i].Reachable != results[j].Reachable {
			return results[i].Reachable
		}
		return results[i].RTT < results[j].RTT
	})

	return results
}

type probeOutcome struct {
	result Result
}

func (e *Engine) probeAddressesWithBudget(ctx context.Context, ips []net.IP, budget time.Duration) []Result {
	budgetCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	outcomes := make(chan probeOutcome, len(ips))
	for _, ip := range ips {
		go func(addr net.IP) {
			result := e.probeOne(budgetCtx, addr)
			if !result.Reachable {
				return
			}

			select {
			case outcomes <- probeOutcome{result: result}:
			case <-budgetCtx.Done():
			}
		}(ip)
	}

	completed := make([]Result, 0, len(ips))
	for {
		select {
		case outcome := <-outcomes:
			completed = append(completed, outcome.result)
			if len(completed) == len(ips) {
				return buildBudgetedResults(ips, completed)
			}
		case <-budgetCtx.Done():
			return buildBudgetedResults(ips, completed)
		}
	}
}

func buildBudgetedResults(original []net.IP, completed []Result) []Result {
	if len(completed) == 0 {
		return nil
	}

	sort.SliceStable(completed, func(i, j int) bool {
		return completed[i].RTT < completed[j].RTT
	})

	results := make([]Result, 0, len(original))
	seen := make(map[string]struct{}, len(completed))
	for _, result := range completed {
		results = append(results, result)
		seen[result.IP.String()] = struct{}{}
	}

	for _, ip := range original {
		if _, ok := seen[ip.String()]; ok {
			continue
		}
		results = append(results, Result{IP: ip})
	}

	return results
}

func (e *Engine) probeOne(ctx context.Context, ip net.IP) Result {
	result := Result{IP: ip}

	switch e.config.Mode {
	case ModeTCP443, ModeBoth:
		rtt, ok := e.probeTCP(ctx, ip, 443)
		if ok {
			result.Reachable = true
			result.RTT = rtt
			return result
		}
	}

	if e.config.Mode == ModeICMP || e.config.Mode == ModeBoth {
		rtt, ok := e.probeTCP(ctx, ip, 80)
		if ok {
			result.Reachable = true
			result.RTT = rtt
			return result
		}
	}

	return result
}

// probeTCP performs a TCP connection probe.
func (e *Engine) probeTCP(ctx context.Context, ip net.IP, port int) (time.Duration, bool) {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	start := time.Now()

	dialer := net.Dialer{Timeout: e.config.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, false
	}
	conn.Close()

	return time.Since(start), true
}

// Enabled returns whether the probe engine is active.
func (e *Engine) Enabled() bool {
	return e.config.Mode != ModeNone
}
