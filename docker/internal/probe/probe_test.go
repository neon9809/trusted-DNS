package probe

import (
	"net"
	"testing"
	"time"
)

func mustIP(t *testing.T, value string) net.IP {
	t.Helper()
	ip := net.ParseIP(value)
	if ip == nil {
		t.Fatalf("failed to parse IP %q", value)
	}
	return ip
}

func TestBuildBudgetedResultsReturnsNilWithoutCompletedProbe(t *testing.T) {
	original := []net.IP{
		mustIP(t, "1.1.1.1"),
		mustIP(t, "8.8.8.8"),
	}

	results := buildBudgetedResults(original, nil)
	if results != nil {
		t.Fatalf("expected nil results when no probes completed, got %v", results)
	}
}

func TestBuildBudgetedResultsKeepsRemainingIPsInOriginalOrder(t *testing.T) {
	original := []net.IP{
		mustIP(t, "1.1.1.1"),
		mustIP(t, "8.8.8.8"),
		mustIP(t, "9.9.9.9"),
	}

	completed := []Result{
		{IP: mustIP(t, "8.8.8.8"), Reachable: true, RTT: 20 * time.Millisecond},
	}

	results := buildBudgetedResults(original, completed)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	expected := []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"}
	for i, want := range expected {
		if got := results[i].IP.String(); got != want {
			t.Fatalf("result %d: expected %s, got %s", i, want, got)
		}
	}
}

func TestBuildBudgetedResultsSortsCompletedByRTT(t *testing.T) {
	original := []net.IP{
		mustIP(t, "1.1.1.1"),
		mustIP(t, "8.8.8.8"),
		mustIP(t, "9.9.9.9"),
	}

	completed := []Result{
		{IP: mustIP(t, "9.9.9.9"), Reachable: true, RTT: 30 * time.Millisecond},
		{IP: mustIP(t, "1.1.1.1"), Reachable: true, RTT: 10 * time.Millisecond},
	}

	results := buildBudgetedResults(original, completed)
	expected := []string{"1.1.1.1", "9.9.9.9", "8.8.8.8"}
	for i, want := range expected {
		if got := results[i].IP.String(); got != want {
			t.Fatalf("result %d: expected %s, got %s", i, want, got)
		}
	}
}
