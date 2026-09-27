package redisdata

import (
	"context"
	"testing"
	"time"
)

func TestPubSub_DeliversToActiveSubscribers(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	ch, unsub, err := p.Subscribe(ctx, "chan1")
	if err != nil {
		t.Fatal(err)
	}
	defer unsub()

	n, err := p.Publish(ctx, "chan1", []byte("hello"))
	if err != nil || n != 1 {
		t.Fatalf("Publish: n=%d err=%v", n, err)
	}

	select {
	case msg := <-ch:
		if msg.Channel != "chan1" || string(msg.Payload) != "hello" {
			t.Fatalf("unexpected message: %+v", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for delivery")
	}
}

func TestPubSub_ZeroSubscribersReturnsZeroNoError(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	n, err := p.Publish(ctx, "nobody-listening", []byte("x"))
	if err != nil || n != 0 {
		t.Fatalf("Publish with no subscribers: n=%d err=%v", n, err)
	}
}

func TestPubSub_MultipleSubscribersAllReceive(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	ch1, unsub1, _ := p.Subscribe(ctx, "c")
	ch2, unsub2, _ := p.Subscribe(ctx, "c")
	defer unsub1()
	defer unsub2()

	n, err := p.Publish(ctx, "c", []byte("m"))
	if err != nil || n != 2 {
		t.Fatalf("Publish: n=%d err=%v", n, err)
	}

	select {
	case msg := <-ch1:
		if string(msg.Payload) != "m" {
			t.Fatalf("ch1 got %q", msg.Payload)
		}
	case <-time.After(time.Second):
		t.Fatal("ch1 timed out")
	}
	select {
	case msg := <-ch2:
		if string(msg.Payload) != "m" {
			t.Fatalf("ch2 got %q", msg.Payload)
		}
	case <-time.After(time.Second):
		t.Fatal("ch2 timed out")
	}
}

func TestPubSub_UnsubscribeStopsDeliveryAndDoesNotLeak(t *testing.T) {
	ctx := context.Background()
	p := newTestPlugin()

	if got := p.ActiveSubscriptions(); got != 0 {
		t.Fatalf("initial ActiveSubscriptions: got %d, want 0", got)
	}

	ch, unsub, err := p.Subscribe(ctx, "c")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.ActiveSubscriptions(); got != 1 {
		t.Fatalf("after Subscribe: got %d, want 1", got)
	}

	unsub()
	if got := p.ActiveSubscriptions(); got != 0 {
		t.Fatalf("after unsubscribe: got %d, want 0 (leak)", got)
	}
	// The channel must be closed, not just abandoned.
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("channel should be closed (or empty+closed), got an unexpected value")
		}
	case <-time.After(time.Second):
		t.Fatal("channel was not closed after unsubscribe")
	}

	// A publish after unsubscribe must not panic or deliver anything.
	n, err := p.Publish(ctx, "c", []byte("late"))
	if err != nil || n != 0 {
		t.Fatalf("Publish after unsubscribe: n=%d err=%v", n, err)
	}

	// Repeated unsub calls must be safe (idempotent).
	unsub()
}
