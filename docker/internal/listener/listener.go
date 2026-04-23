// Package listener implements the DNS UDP listener that accepts
// standard DNS queries on port 53 and dispatches them for processing.
package listener

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
)

// Handler is the callback for processing DNS queries.
// It receives the raw DNS wire-format query and returns the response.
type Handler func(ctx context.Context, query []byte) ([]byte, error)

// Listener manages the UDP DNS listener on port 53.
type Listener struct {
	addr    string
	conn    *net.UDPConn
	handler Handler
	wg      sync.WaitGroup
	done    chan struct{}
}

// New creates a new DNS listener.
func New(addr string, handler Handler) *Listener {
	return &Listener{
		addr:    addr,
		handler: handler,
		done:    make(chan struct{}),
	}
}

// Start begins listening for DNS queries.
func (l *Listener) Start() error {
	udpAddr, err := net.ResolveUDPAddr("udp", l.addr)
	if err != nil {
		return fmt.Errorf("resolve addr: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	l.conn = conn

	log.Printf("[listener] DNS listener started on %s", l.addr)

	l.wg.Add(1)
	go l.readLoop()

	return nil
}

// Stop gracefully shuts down the listener.
func (l *Listener) Stop() {
	close(l.done)
	if l.conn != nil {
		l.conn.Close()
	}
	l.wg.Wait()
	log.Println("[listener] DNS listener stopped")
}

func (l *Listener) readLoop() {
	defer l.wg.Done()

	buf := make([]byte, 4096) // DNS over UDP max is typically 512 or 4096 with EDNS

	for {
		select {
		case <-l.done:
			return
		default:
		}

		n, remoteAddr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-l.done:
				return
			default:
				log.Printf("[listener] read error: %v", err)
				continue
			}
		}

		if n < 12 { // minimum DNS header size
			continue
		}

		// Copy the query data to avoid buffer reuse issues
		query := make([]byte, n)
		copy(query, buf[:n])

		// Handle in a goroutine for concurrency
		l.wg.Add(1)
		go func(q []byte, addr *net.UDPAddr) {
			defer l.wg.Done()
			l.handleQuery(q, addr)
		}(query, remoteAddr)
	}
}

func (l *Listener) handleQuery(query []byte, addr *net.UDPAddr) {
	ctx := context.Background()

	resp, err := l.handler(ctx, query)
	if err != nil {
		log.Printf("[listener] handler error for %s: %v", addr, err)
		// Send SERVFAIL response
		resp = buildServfail(query)
	}

	if resp != nil {
		if _, err := l.conn.WriteToUDP(resp, addr); err != nil {
			log.Printf("[listener] write error to %s: %v", addr, err)
		}
	}
}

// buildServfail creates a minimal DNS SERVFAIL response.
func buildServfail(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	resp := make([]byte, len(query))
	copy(resp, query)

	// Set QR bit (response) and RCODE = SERVFAIL (2)
	resp[2] = (query[2] & 0x01) | 0x80 // QR=1, keep RD
	resp[3] = (query[3] & 0x00) | 0x02 // RCODE=SERVFAIL
	// Zero out answer/authority/additional counts
	resp[6] = 0; resp[7] = 0
	resp[8] = 0; resp[9] = 0
	resp[10] = 0; resp[11] = 0

	return resp[:12+questionLen(query)]
}

// questionLen returns the length of the Question section.
func questionLen(query []byte) int {
	if len(query) < 12 {
		return 0
	}
	off := 12
	// Skip QNAME (sequence of labels ending with 0)
	for off < len(query) {
		labelLen := int(query[off])
		if labelLen == 0 {
			off++ // skip the zero byte
			break
		}
		off += 1 + labelLen
	}
	// QTYPE (2) + QCLASS (2)
	off += 4
	if off > len(query) {
		return len(query) - 12
	}
	return off - 12
}
