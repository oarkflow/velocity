package resp

import (
	"context"
	"sync"

	"github.com/oarkflow/velocity/v2/api"
)

// cmdSubscribe implements real Redis subscriber-mode behavior: after
// SUBSCRIBE, the connection sends one confirmation push per channel, then
// stays open streaming "message" pushes as they arrive, until the client
// disconnects. It takes over the connection's read/write loop entirely —
// handleConn calls this and then returns without reading again, so there
// is exactly one goroutine reading from r at any time (a background
// goroutine here takes over reading, solely to detect connection close;
// it never writes, so there is exactly one writer too).
func (p *Plugin) cmdSubscribe(ctx context.Context, r *Reader, w *Writer, args []string) {
	if p.pubsub == nil {
		w.WriteError(errNoDataStructures)
		w.Flush()
		return
	}
	if len(args) < 2 {
		w.WriteError(wrongArgs("SUBSCRIBE"))
		w.Flush()
		return
	}
	channels := args[1:]

	type subscription struct {
		ch     <-chan api.PubSubMessage
		cancel func()
	}
	subs := make([]subscription, 0, len(channels))
	defer func() {
		for _, s := range subs {
			s.cancel()
		}
	}()

	count := int64(0)
	for _, chName := range channels {
		ch, cancel, err := p.pubsub.Subscribe(ctx, chName)
		if err != nil {
			w.WriteError("ERR " + err.Error())
			continue
		}
		subs = append(subs, subscription{ch: ch, cancel: cancel})
		count++
		w.WriteArrayHeader(3)
		w.WriteBulkString([]byte("subscribe"))
		w.WriteBulkString([]byte(chName))
		w.WriteInteger(count)
	}
	if err := w.Flush(); err != nil {
		return
	}
	if len(subs) == 0 {
		return
	}

	// Merge every subscribed channel's messages into one Go channel so a
	// single select loop below can serve them all.
	merged := make(chan api.PubSubMessage)
	stopMerge := make(chan struct{})
	var mergeWG sync.WaitGroup
	for _, s := range subs {
		mergeWG.Add(1)
		go func(c <-chan api.PubSubMessage) {
			defer mergeWG.Done()
			for {
				select {
				case m, ok := <-c:
					if !ok {
						return
					}
					select {
					case merged <- m:
					case <-stopMerge:
						return
					}
				case <-stopMerge:
					return
				}
			}
		}(s.ch)
	}
	go func() {
		mergeWG.Wait()
		close(merged)
	}()
	defer close(stopMerge)

	// The only remaining reader on this connection: its sole purpose is
	// detecting client disconnect (or a protocol error), since a
	// subscriber-mode client typically sends nothing further. Real Redis
	// also accepts further SUBSCRIBE/UNSUBSCRIBE/PING while subscribed;
	// that richer behavior is a documented follow-up, not implemented
	// here — this reader discards any further input.
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			if _, err := r.ReadCommand(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case m, ok := <-merged:
			if !ok {
				return
			}
			w.WriteArrayHeader(3)
			w.WriteBulkString([]byte("message"))
			w.WriteBulkString([]byte(m.Channel))
			w.WriteBulkString(m.Payload)
			if err := w.Flush(); err != nil {
				return
			}
		case <-closed:
			return
		case <-ctx.Done():
			return
		}
	}
}
