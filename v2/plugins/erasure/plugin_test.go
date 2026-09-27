package erasure

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// memBackend is a minimal in-test api.StorageBackend stub, so this
// package's tests don't depend on plugins/storage-mem (another agent's
// in-flight package).
type memBackend struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemBackend() *memBackend { return &memBackend{data: make(map[string][]byte)} }

func (m *memBackend) Get(ctx context.Context, key []byte) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[string(key)]
	if !ok {
		return nil, false, nil
	}
	cp := append([]byte(nil), v...)
	return cp, true, nil
}

func (m *memBackend) Put(ctx context.Context, e api.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[string(e.Key)] = append([]byte(nil), e.Value...)
	return nil
}

func (m *memBackend) Delete(ctx context.Context, key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, string(key))
	return nil
}

func (m *memBackend) Batch(ctx context.Context, ops []api.BatchOp) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, op := range ops {
		if op.Delete {
			delete(m.data, string(op.Entry.Key))
		} else {
			m.data[string(op.Entry.Key)] = append([]byte(nil), op.Entry.Value...)
		}
	}
	return nil
}

func (m *memBackend) Scan(ctx context.Context, prefix []byte) (api.Iterator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []string
	for k := range m.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == string(prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return &memIterator{backend: m, keys: keys, idx: -1}, nil
}

func (m *memBackend) Snapshot(ctx context.Context) (api.Snapshot, error) {
	return nil, errors.New("not implemented in test stub")
}

func (m *memBackend) Close() error { return nil }

type memIterator struct {
	backend *memBackend
	keys    []string
	idx     int
}

func (it *memIterator) Next() bool {
	it.idx++
	return it.idx < len(it.keys)
}
func (it *memIterator) Key() []byte { return []byte(it.keys[it.idx]) }
func (it *memIterator) Value() []byte {
	it.backend.mu.Lock()
	defer it.backend.mu.Unlock()
	return it.backend.data[it.keys[it.idx]]
}
func (it *memIterator) Err() error   { return nil }
func (it *memIterator) Close() error { return nil }

// corrupt directly mutates a shard's stored bytes via the backend,
// simulating bit rot.
func corrupt(t *testing.T, mb *memBackend, key []byte) {
	t.Helper()
	mb.mu.Lock()
	defer mb.mu.Unlock()
	v, ok := mb.data[string(key)]
	if !ok || len(v) == 0 {
		t.Fatalf("cannot corrupt missing/empty key %q", key)
	}
	v[0] ^= 0xFF
}

func newTestPlugin(t *testing.T) (*Plugin, *memBackend) {
	t.Helper()
	p := NewPlugin("storage-lsm")
	mb := newMemBackend()
	codec, err := NewCodec(p.config)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	p.codec = codec
	p.storage = mb
	p.health = api.Health{Status: "ok"}
	return p, mb
}

func TestShardStoreRoundTripAndHeal(t *testing.T) {
	ctx := context.Background()
	p, mb := newTestPlugin(t)

	data := []byte("shard store round trip must reconstruct after corruption is healed")
	if err := p.StoreShards(ctx, "obj-1", data); err != nil {
		t.Fatalf("StoreShards: %v", err)
	}

	got, err := p.ReadShards(ctx, "obj-1")
	if err != nil {
		t.Fatalf("ReadShards (no corruption): %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("mismatch before corruption: got %q want %q", got, data)
	}

	ok, corruptIdx, err := p.VerifyShards(ctx, "obj-1")
	if err != nil || !ok || len(corruptIdx) != 0 {
		t.Fatalf("VerifyShards before corruption: ok=%v corrupt=%v err=%v", ok, corruptIdx, err)
	}

	// Simulate bit rot on shard 0.
	corrupt(t, mb, shardKey("obj-1", 0))

	ok, corruptIdx, err = p.VerifyShards(ctx, "obj-1")
	if err != nil {
		t.Fatalf("VerifyShards after corruption: %v", err)
	}
	if ok || len(corruptIdx) == 0 {
		t.Fatalf("expected VerifyShards to detect corruption, got ok=%v corrupt=%v", ok, corruptIdx)
	}

	// Even with one shard corrupted, reconstruction should still succeed
	// (parity covers it).
	got, err = p.ReadShards(ctx, "obj-1")
	if err != nil {
		t.Fatalf("ReadShards after corruption: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("mismatch after corruption (should reconstruct via parity): got %q want %q", got, data)
	}

	if err := p.HealShards(ctx, "obj-1"); err != nil {
		t.Fatalf("HealShards: %v", err)
	}

	ok, corruptIdx, err = p.VerifyShards(ctx, "obj-1")
	if err != nil || !ok || len(corruptIdx) != 0 {
		t.Fatalf("VerifyShards after heal: ok=%v corrupt=%v err=%v", ok, corruptIdx, err)
	}
}

func TestBackgroundScanHealsWithoutExplicitCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, mb := newTestPlugin(t)
	p.scanEvery = 50 * time.Millisecond
	p.ids["obj-2"] = struct{}{}

	data := []byte("background self-healing must repair corruption without an explicit call")
	if err := p.StoreShards(ctx, "obj-2", data); err != nil {
		t.Fatalf("StoreShards: %v", err)
	}
	corrupt(t, mb, shardKey("obj-2", 1))

	if ok, _, err := p.VerifyShards(ctx, "obj-2"); err != nil || ok {
		t.Fatalf("expected corruption present before scan loop runs, ok=%v err=%v", ok, err)
	}

	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := p.Stop(ctx); err != nil {
			t.Fatalf("Stop: %v", err)
		}
	}()

	deadline := time.After(2 * time.Second)
	for {
		ok, _, err := p.VerifyShards(ctx, "obj-2")
		if err != nil {
			t.Fatalf("VerifyShards during poll: %v", err)
		}
		if ok {
			break // background loop healed it
		}
		select {
		case <-deadline:
			t.Fatalf("background scan loop did not heal shard set within timeout")
		case <-time.After(20 * time.Millisecond):
		}
	}
}
