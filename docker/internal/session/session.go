// Package session manages the KeyBundle lifecycle, ticket rotation,
// and sequence number tracking for the Docker node.
package session

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/neon9809/trusted-dns/docker/internal/protocol"
)

// Manager handles the session state for the Docker node.
type Manager struct {
	mu                   sync.RWMutex
	bundle               *protocol.KeyBundle
	keys                 *protocol.DerivedKeys
	clientID             []byte
	queryKeys            []*protocol.QueryKeys // one per session ticket
	seqCounters          []uint32              // current seq for each ticket
	totalQueries         uint32                // total queries across all tickets
	currentSlot          int32                 // current ticket slot (atomic)
	rebootstrapTriggered atomic.Int64          // timestamp when re-bootstrap was triggered (UnixNano, 0 = not triggered)
}

// New creates a new session manager.
func New(keys *protocol.DerivedKeys, clientID []byte) *Manager {
	return &Manager{
		keys:     keys,
		clientID: clientID,
	}
}

// SetBundle installs a new KeyBundle and derives query keys.
func (m *Manager) SetBundle(bundle *protocol.KeyBundle) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.bundle = bundle
	m.queryKeys = make([]*protocol.QueryKeys, len(bundle.SessionTickets))
	m.seqCounters = make([]uint32, len(bundle.SessionTickets))
	m.totalQueries = 0
	atomic.StoreInt32(&m.currentSlot, 0)

	for i, ticket := range bundle.SessionTickets {
		qk, err := protocol.DeriveQueryKeys(ticket.ResumeSeed[:])
		if err != nil {
			return fmt.Errorf("derive query keys for slot %d: %w", i, err)
		}
		m.queryKeys[i] = qk
		m.seqCounters[i] = ticket.CounterBase
	}

	// Cancel any pending re-bootstrap countdown since we have a valid bundle now
	m.rebootstrapTriggered.Store(0)

	log.Printf("[session] installed bundle gen=%d with %d tickets, budget=%d",
		bundle.BundleGen, len(bundle.SessionTickets), bundle.Policy.QueriesPerBundle)

	return nil
}

// GetBundle returns the current KeyBundle.
func (m *Manager) GetBundle() *protocol.KeyBundle {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bundle
}

// TicketInfo holds the information needed to send a query.
type TicketInfo struct {
	Ticket    *protocol.SessionTicket
	QueryKeys *protocol.QueryKeys
	Seq       uint32
	Slot      int
}

// AcquireTicket selects the current ticket and increments the sequence number.
// Returns nil if no tickets are available or budget is exhausted.
func (m *Manager) AcquireTicket() (*TicketInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.bundle == nil {
		return nil, fmt.Errorf("no active bundle")
	}

	// Check total budget
	if m.totalQueries >= uint32(m.bundle.Policy.QueriesPerBundle) {
		return nil, fmt.Errorf("bundle query budget exhausted")
	}

	slot := int(atomic.LoadInt32(&m.currentSlot))

	// Find a ticket with remaining budget
	for attempts := 0; attempts < len(m.bundle.SessionTickets); attempts++ {
		ticket := m.bundle.SessionTickets[slot]
		seq := m.seqCounters[slot]

		if seq < ticket.CounterBase+uint32(ticket.QueryBudget) {
			m.seqCounters[slot]++
			m.totalQueries++

			info := &TicketInfo{
				Ticket:    ticket,
				QueryKeys: m.queryKeys[slot],
				Seq:       seq,
				Slot:      slot,
			}

				// Rotate to next ticket if this one is near exhaustion
				if m.seqCounters[slot] >= ticket.CounterBase+uint32(ticket.QueryBudget) {
					nextSlot := (slot + 1) % len(m.bundle.SessionTickets)
					atomic.StoreInt32(&m.currentSlot, int32(nextSlot))
					log.Printf("[session] ticket slot %d exhausted (seq=%d), rotating to slot %d", slot, m.seqCounters[slot], nextSlot)
				}

			return info, nil
		}

		// This ticket is exhausted, try next
		slot = (slot + 1) % len(m.bundle.SessionTickets)
		atomic.StoreInt32(&m.currentSlot, int32(slot))
	}

	return nil, fmt.Errorf("all tickets exhausted")
}

// NeedsRefresh returns true if the bundle is near exhaustion.
func (m *Manager) NeedsRefresh() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.bundle == nil {
		return true
	}

	threshold := uint32(float64(m.bundle.Policy.QueriesPerBundle) * 0.9)
	needs := m.totalQueries >= threshold
	if needs {
		log.Printf("[session] refresh needed: totalQueries=%d >= threshold=%d (budget=%d)",
			m.totalQueries, threshold, m.bundle.Policy.QueriesPerBundle)
	}
	return needs
}

// HasBundle returns true if there's an active bundle.
func (m *Manager) HasBundle() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bundle != nil
}

// GetRefreshTicket returns the refresh ticket for the current bundle.
func (m *Manager) GetRefreshTicket() *protocol.RefreshTicket {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.bundle == nil {
		return nil
	}
	return m.bundle.RefreshTicket
}

// GetTotalQueries returns the total number of queries made.
func (m *Manager) GetTotalQueries() uint32 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.totalQueries
}

// GetClientIDPrefix returns the first 8 bytes of the client ID.
func (m *Manager) GetClientIDPrefix() [8]byte {
	var prefix [8]byte
	if len(m.clientID) >= 8 {
		copy(prefix[:], m.clientID[:8])
	}
	return prefix
}

// GetClientID returns the full client ID.
func (m *Manager) GetClientID() []byte {
	return m.clientID
}

// ClearBundle clears the current bundle, forcing a re-bootstrap.
// This should be called when the Worker rejects tickets (ERR_BAD_TICKET).
func (m *Manager) ClearBundle() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.bundle = nil
	m.queryKeys = nil
	m.seqCounters = nil
	m.totalQueries = 0
	atomic.StoreInt32(&m.currentSlot, 0)

	log.Println("[session] bundle cleared, re-bootstrap required")
}

// TriggerRebootstrap schedules a re-bootstrap after 1 minute delay.
// Returns true if this is the first trigger, false if already triggered.
// Multiple concurrent calls will only trigger one re-bootstrap countdown.
func (m *Manager) TriggerRebootstrap() bool {
	// Check if already triggered
	currentTrigger := m.rebootstrapTriggered.Load()
	if currentTrigger != 0 {
		return false // Already triggered
	}

	// Try to set the trigger timestamp (atomic CAS)
	triggeredAt := time.Now().UnixNano()
	if !m.rebootstrapTriggered.CompareAndSwap(0, triggeredAt) {
		return false // Another goroutine triggered it first
	}

	log.Printf("[session] re-bootstrap countdown started (1 minute delay)")
	return true
}

// ShouldRebootstrap checks if the 1-minute countdown has elapsed and re-bootstrap should proceed.
// Returns true if countdown elapsed and this call won the race to perform re-bootstrap.
// Uses atomic CAS to ensure only one goroutine can win the race.
func (m *Manager) ShouldRebootstrap() bool {
	triggeredAt := m.rebootstrapTriggered.Load()
	if triggeredAt == 0 {
		return false // Not triggered
	}

	// Check if 1 minute has elapsed
	elapsed := time.Since(time.Unix(0, triggeredAt))
	if elapsed < time.Minute {
		remaining := time.Minute - elapsed
		log.Printf("[session] re-bootstrap countdown: %v remaining", remaining.Round(time.Second))
		return false
	}

	// Atomically try to claim the re-bootstrap right
	// Only one goroutine will succeed in this CAS and return true
	if !m.rebootstrapTriggered.CompareAndSwap(triggeredAt, 0) {
		// Another goroutine already claimed it
		log.Println("[session] re-bootstrap already claimed by another goroutine")
		return false
	}

	return true
}

// CancelRebootstrap cancels a pending re-bootstrap countdown.
func (m *Manager) CancelRebootstrap() {
	triggeredAt := m.rebootstrapTriggered.Load()
	if triggeredAt != 0 {
		m.rebootstrapTriggered.Store(0)
		log.Println("[session] re-bootstrap countdown cancelled")
	}
}
