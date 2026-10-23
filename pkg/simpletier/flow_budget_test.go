package simpletier

import (
	"testing"

	"github.com/yiiilin/simpletier/internal/budget"
)

// TestFlowBufferBudgetAccountsAndReleases proves the Flow BufferBudget adapter
// books every reservation into the shared Allocator heap, releases on Release
// and on Close, and leaks nothing after Close. It is the direct evidence that
// production Flow no longer uses a local self-bound budget.
func TestFlowBufferBudgetAccountsAndReleases(t *testing.T) {
	alloc, err := budget.New(budget.NetworkID(0x1234), budget.DefaultLimits())
	if err != nil {
		t.Fatalf("budget.New: %v", err)
	}
	b := newFlowBufferBudget(alloc, 0x1234)

	if err := b.Reserve(4096); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if got := alloc.Stats().Heap.Bytes; got != 4096 {
		t.Fatalf("Heap.Bytes after Reserve = %d; want 4096", got)
	}
	b.Release(4096)
	if got := alloc.Stats().Heap.Bytes; got != 0 {
		t.Fatalf("Heap.Bytes after Release = %d; want 0", got)
	}

	if err := b.Reserve(2048); err != nil {
		t.Fatalf("Reserve(close): %v", err)
	}
	if err := b.Reserve(2048); err != nil {
		t.Fatalf("Reserve(close) second: %v", err)
	}
	b.Close()
	b.Close() // idempotent
	if got := alloc.Stats().Heap.Bytes; got != 0 {
		t.Fatalf("Heap.Bytes after Close = %d; want 0", got)
	}
	if err := b.Reserve(1); err == nil {
		t.Fatal("Reserve after Close succeeded; want closed error")
	}

	if err := alloc.Close(); err != nil {
		t.Fatalf("allocator.Close: %v", err)
	}
	stats := alloc.Stats()
	if stats.LeakedBytes != 0 || stats.LeakedFrames != 0 {
		t.Fatalf("leaked after allocator.Close: bytes=%d frames=%d", stats.LeakedBytes, stats.LeakedFrames)
	}
}
