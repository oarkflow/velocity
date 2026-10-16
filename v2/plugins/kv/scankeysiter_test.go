package kv

import (
	"context"
	"testing"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// Tests for the api.KVKeysIter capability (ScanKeysIter/ScanKeysIterFrom):
// the byte-callback sibling of ScanKeysStream with a seek variant. The
// property that matters everywhere is PARITY: whatever backend shape
// (seekable or skip-fallback), the keys delivered — and stopped-at —
// must be exactly what a string-key walk over the same prefix would
// deliver, minus (for the From variant) the keys that sort strictly
// before startKey.

func TestScanKeysIter_ParityWithScanKeysStream(t *testing.T) {
	ctx := context.Background()
	for _, backend := range []string{"plain", "ranged"} {
		t.Run(backend, func(t *testing.T) {
			var p *Plugin
			switch backend {
			case "plain":
				p = &Plugin{storage: newMemBackend()}
			default:
				p = &Plugin{storage: &rangedBackend{memBackend: newMemBackend()}}
			}
			seedN(t, p, "k:", 100)
			seedN(t, p, "other:", 10) // prove prefix filtering applies too

			var got []string
			err := p.ScanKeysIter(ctx, "k:", func(key []byte) (bool, error) {
				got = append(got, string(key)) // copy: callback bytes are transient
				return true, nil
			})
			if err != nil {
				t.Fatalf("ScanKeysIter: %v", err)
			}
			var want []string
			if err := p.ScanKeysStream(ctx, "k:", func(key string) (bool, error) {
				want = append(want, key)
				return true, nil
			}); err != nil {
				t.Fatalf("ScanKeysStream: %v", err)
			}
			if !equalStrings(got, want) {
				t.Fatalf("byte walk %v != string walk %v", got, want)
			}
		})
	}
}

func TestScanKeysIter_EarlyStop(t *testing.T) {
	ctx := context.Background()
	p := &Plugin{storage: newMemBackend()}
	seedN(t, p, "k:", 52)

	calls := 0
	err := p.ScanKeysIter(ctx, "k:", func(key []byte) (bool, error) {
		calls++
		return calls < 7, nil
	})
	if err != nil {
		t.Fatalf("ScanKeysIter: %v", err)
	}
	if calls != 7 {
		t.Fatalf("callback fired %d times, want 7 (stop request must end the walk)", calls)
	}
}

func TestScanKeysIterFrom_ParityWithFilteredStringWalk(t *testing.T) {
	ctx := context.Background()
	seeds := []string{"k:000", "k:001", "k:003", "k:007", "k:010"}
	startKeys := []string{
		"",      // empty: exactly ScanKeysIter
		"k:000", // exact existing key: starts AT it (inclusive)
		"k:002", // between keys: first key greater
		"k:009", // between (after last): none but then... "k:010" and beyond
		"k:010", // last key exactly
		"k:999", // past everything: nothing
		"a:000", // before everything: all
	}

	for _, backend := range []string{"plain", "ranged"} {
		t.Run(backend, func(t *testing.T) {
			var p *Plugin
			switch backend {
			case "plain":
				// No RangedScanner — the fallback must skip forward itself.
				p = &Plugin{storage: newMemBackend()}
			default:
				p = &Plugin{storage: &rangedBackend{memBackend: newMemBackend()}}
			}
			for _, seed := range seeds {
				if err := p.Put(ctx, seed, []byte("v")); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.Put(ctx, "j:999", []byte("v")); err != nil {
				t.Fatal(err) // sorts before every seed: proves prefix filtering + skip interplay
			}

			var streamAll []string
			if err := p.ScanKeysStream(ctx, "k:", func(key string) (bool, error) {
				streamAll = append(streamAll, key)
				return true, nil
			}); err != nil {
				t.Fatalf("ScanKeysStream: %v", err)
			}

			for _, start := range startKeys {
				var want []string
				for _, k := range streamAll {
					if start == "" || k >= start {
						want = append(want, k)
					}
				}
				var got []string
				err := p.ScanKeysIterFrom(ctx, "k:", start, func(key []byte) (bool, error) {
					got = append(got, string(key))
					return true, nil
				})
				if err != nil {
					t.Fatalf("start=%q: %v", start, err)
				}
				if !equalStrings(got, want) {
					t.Fatalf("start=%q: walked %v, want %v", start, got, want)
				}
			}
		})
	}
}

func TestScanKeysIterFrom_EarlyStopStopsEarly(t *testing.T) {
	ctx := context.Background()
	p := &Plugin{storage: &rangedBackend{memBackend: newMemBackend()}}
	seedN(t, p, "k:", 50)

	calls := 0
	err := p.ScanKeysIterFrom(ctx, "k:", "k:020", func(key []byte) (bool, error) {
		calls++
		return calls < 3, nil
	})
	if err != nil {
		t.Fatalf("ScanKeysIterFrom: %v", err)
	}
	if calls != 3 {
		t.Fatalf("callback fired %d times, want 3", calls)
	}
}

// TestScanKeysIter_ImplementsOptionalCapability guards the interface's
// optional-assertion contract: a Plugin satisfies BOTH methods as one
// coherent surface, and a caller must be able to detect its absence via
// plain type assertion on any KVService.
func TestScanKeysIter_ImplementsOptionalCapability(t *testing.T) {
	p := &Plugin{storage: newMemBackend()}
	var asIter api.KVKeysIter = p // compiles only if Plugin implements it
	_ = asIter

	// A KVService lacking the capability must fail the assertion.
	var anyKV api.KVService = stubKV{}
	if _, ok := anyKV.(api.KVKeysIter); ok {
		t.Fatal("a bare KVService must NOT satisfy api.KVKeysIter")
	}
}

type stubKV struct{}

func (s stubKV) Put(context.Context, string, []byte) error                       { return nil }
func (s stubKV) PutWithTTL(context.Context, string, []byte, time.Duration) error { return nil }
func (s stubKV) Get(context.Context, string) ([]byte, bool, error)               { return nil, false, nil }
func (s stubKV) Delete(context.Context, string) error                            { return nil }
func (s stubKV) Exists(context.Context, string) (bool, error)                    { return false, nil }
func (s stubKV) Incr(context.Context, string, int64) (int64, error)              { return 0, nil }
func (s stubKV) Keys(context.Context, string) ([]string, error)                  { return nil, nil }
func (s stubKV) Scan(context.Context, string, int, string) (map[string][]byte, string, error) {
	return nil, "", nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
