package secret

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
)

// TestConcurrentSetDifferentNames stresses many goroutines concurrently
// Set-ing distinct secret names — every secret must be correctly
// retrievable afterward, no data race, no lost writes.
func TestConcurrentSetDifferentNames(t *testing.T) {
	ctx := context.Background()
	p, _ := newSecretPlugin(t)

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("secret-%03d", i)
			val := fmt.Sprintf("value-%03d", i)
			if _, err := p.Set(ctx, name, []byte(val)); err != nil {
				t.Errorf("Set(%s): %v", name, err)
			}
		}(i)
	}
	wg.Wait()

	var wg2 sync.WaitGroup
	for i := 0; i < n; i++ {
		wg2.Add(1)
		go func(i int) {
			defer wg2.Done()
			name := fmt.Sprintf("secret-%03d", i)
			want := fmt.Sprintf("value-%03d", i)
			got, err := p.Get(ctx, name, 0)
			if err != nil {
				t.Errorf("Get(%s): %v", name, err)
				return
			}
			if !bytes.Equal(got, []byte(want)) {
				t.Errorf("Get(%s): got %q, want %q", name, got, want)
			}
		}(i)
	}
	wg2.Wait()
}

// TestConcurrentGetRotateSharedName exercises concurrent Get and Rotate
// calls against the SAME secret name — no data race, no lost/corrupted
// value, and Versions() must reflect a consistent (monotonically
// increasing, gap-free) history afterward even though Rotate doesn't
// change the version number (it re-seals in place), so the only source
// of new versions here is none — this test's Rotate calls are pure
// re-encryption, and the point is proving concurrent Get+Rotate never
// corrupts the single existing version.
func TestConcurrentGetRotateSharedName(t *testing.T) {
	ctx := context.Background()
	p, _ := newSecretPlugin(t)

	if _, err := p.Set(ctx, "shared", []byte("stable-value")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				if err := p.Rotate(ctx, "shared"); err != nil {
					t.Errorf("Rotate: %v", err)
				}
				return
			}
			got, err := p.Get(ctx, "shared", 0)
			if err != nil {
				t.Errorf("Get: %v", err)
				return
			}
			if !bytes.Equal(got, []byte("stable-value")) {
				t.Errorf("Get during concurrent Rotate: got %q, want %q (torn/corrupted read)", got, "stable-value")
			}
		}(i)
	}
	wg.Wait()

	// Final sanity: value still correct, and there's still exactly one
	// version (Rotate never creates a new one).
	final, err := p.Get(ctx, "shared", 0)
	if err != nil {
		t.Fatalf("final Get: %v", err)
	}
	if !bytes.Equal(final, []byte("stable-value")) {
		t.Fatalf("final value corrupted: got %q", final)
	}
	versions, err := p.Versions(ctx, "shared")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(versions) != 1 {
		t.Fatalf("expected exactly 1 version after concurrent Get+Rotate, got %d", len(versions))
	}
}

// TestConcurrentSetSameNameProducesConsistentVersioning fires many
// concurrent Set calls at the SAME secret name — Set's own p.mu.Lock
// serializes the read-latest-then-write-next-version sequence, so this
// proves that serialization actually holds under real concurrent load: no
// two writers may end up assigned the same version number, and the final
// Versions() list must be a gap-free 1..N sequence.
func TestConcurrentSetSameNameProducesConsistentVersioning(t *testing.T) {
	ctx := context.Background()
	p, _ := newSecretPlugin(t)

	const n = 40
	var wg sync.WaitGroup
	versions := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, err := p.Set(ctx, "versioned", []byte(fmt.Sprintf("v-from-writer-%03d", i)))
			if err != nil {
				t.Errorf("Set writer %d: %v", i, err)
				return
			}
			versions[i] = v
		}(i)
	}
	wg.Wait()

	seen := make(map[int]bool, n)
	for i, v := range versions {
		if v == 0 {
			t.Fatalf("writer %d never got a version number", i)
		}
		if seen[v] {
			t.Fatalf("version number collision: %d assigned to more than one writer (Set's mutex is not serializing correctly)", v)
		}
		seen[v] = true
	}

	all, err := p.Versions(ctx, "versioned")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(all) != n {
		t.Fatalf("expected %d versions, got %d", n, len(all))
	}
	for v := 1; v <= n; v++ {
		if !seen[v] {
			t.Fatalf("version sequence has a gap: %d was never assigned to any writer", v)
		}
	}
}
