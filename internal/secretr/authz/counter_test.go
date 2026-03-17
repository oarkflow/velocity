package authz

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	licclient "github.com/oarkflow/licensing-go"
)

func TestMemoryUsageCounter_WindowReset(t *testing.T) {
	c := NewMemoryUsageCounter()
	ctx := context.Background()

	if err := c.Consume(ctx, "secret:read", licclient.SubjectTypeUser, "u1", 1, 1, 2); err != nil {
		t.Fatalf("first consume failed: %v", err)
	}
	if err := c.Consume(ctx, "secret:read", licclient.SubjectTypeUser, "u1", 1, 1, 2); err != nil {
		t.Fatalf("second consume failed: %v", err)
	}
	if err := c.Consume(ctx, "secret:read", licclient.SubjectTypeUser, "u1", 1, 1, 2); err == nil {
		t.Fatal("expected limit exceeded before window reset")
	}

	time.Sleep(1100 * time.Millisecond)
	if err := c.Consume(ctx, "secret:read", licclient.SubjectTypeUser, "u1", 1, 1, 2); err != nil {
		t.Fatalf("expected consume after reset, got: %v", err)
	}
}

func TestMemoryUsageCounter_Concurrent(t *testing.T) {
	c := NewMemoryUsageCounter()
	ctx := context.Background()
	const limit = 50
	const workers = 200

	var okCount int32
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Consume(ctx, "secret:read", licclient.SubjectTypeUser, "u1", 1, 0, limit); err == nil {
				atomic.AddInt32(&okCount, 1)
			}
		}()
	}
	wg.Wait()
	if okCount != limit {
		t.Fatalf("expected exactly %d successful consumes, got %d", limit, okCount)
	}
}
