package session

import (
	"testing"

	"github.com/neon9809/trusted-dns/docker/internal/protocol"
)

func TestSetBundleIfGenMatches(t *testing.T) {
	sess := New(nil, make([]byte, protocol.ClientIDSize))

	if err := sess.SetBundle(testBundle(1, 0x01)); err != nil {
		t.Fatalf("set initial bundle: %v", err)
	}

	applied, err := sess.SetBundleIfGenMatches(1, testBundle(2, 0x02))
	if err != nil {
		t.Fatalf("set matching bundle: %v", err)
	}
	if !applied {
		t.Fatalf("expected matching generation update to apply")
	}

	gen, ok := sess.GetBundleGen()
	if !ok || gen != 2 {
		t.Fatalf("expected bundle gen=2 after apply, got gen=%d ok=%v", gen, ok)
	}

	applied, err = sess.SetBundleIfGenMatches(1, testBundle(3, 0x03))
	if err != nil {
		t.Fatalf("set stale bundle: %v", err)
	}
	if applied {
		t.Fatalf("expected stale generation update to be ignored")
	}

	gen, ok = sess.GetBundleGen()
	if !ok || gen != 2 {
		t.Fatalf("expected bundle gen=2 after stale apply attempt, got gen=%d ok=%v", gen, ok)
	}
}

func TestClearBundleIfGenMatches(t *testing.T) {
	sess := New(nil, make([]byte, protocol.ClientIDSize))

	if err := sess.SetBundle(testBundle(5, 0x05)); err != nil {
		t.Fatalf("set initial bundle: %v", err)
	}

	if cleared := sess.ClearBundleIfGenMatches(4); cleared {
		t.Fatalf("expected mismatched generation clear to be ignored")
	}
	if !sess.HasBundle() {
		t.Fatalf("expected bundle to remain installed after mismatched clear")
	}

	if cleared := sess.ClearBundleIfGenMatches(5); !cleared {
		t.Fatalf("expected matching generation clear to succeed")
	}
	if sess.HasBundle() {
		t.Fatalf("expected bundle to be cleared")
	}
}

func testBundle(gen uint64, seedByte byte) *protocol.KeyBundle {
	var resumeSeed [protocol.ResumeSeedSize]byte
	resumeSeed[0] = seedByte

	return &protocol.KeyBundle{
		BundleGen: gen,
		Policy:    protocol.DefaultPolicy(),
		SessionTickets: []*protocol.SessionTicket{
			{
				TicketID:    1,
				QueryBudget: 1,
				CounterBase: 0,
				ResumeSeed:  resumeSeed,
			},
		},
		RefreshTicket: &protocol.RefreshTicket{
			BundleGen: gen,
		},
	}
}
