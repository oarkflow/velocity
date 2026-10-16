package sql

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

// Capability-surface adapters around memKV, so each of rangeLookupPKs's
// three walk routes (byte-keys+seek, string-keys stream, paged fallback)
// can be forced independently against the SAME data. All walk a sorted
// key snapshot taken under memKV's mutex, so none needs to worry about
// concurrent mutation — these tests don't mutate mid-scan.

// streamOnlyKV exposes ONLY the string-key stream capability.
type streamOnlyKV struct{ *memKV }

var _ api.KVStreamScanner = (*streamOnlyKV)(nil)

func kvKeysUnder(m *memKV, prefix string) ([]string, map[string][]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.data))
	for k := range m.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	vals := make(map[string][]byte, len(keys))
	for _, k := range keys {
		cp := make([]byte, len(m.data[k]))
		copy(cp, m.data[k])
		vals[k] = cp
	}
	return keys, vals
}

func (s *streamOnlyKV) ScanStream(ctx context.Context, prefix string, fn func(k string, v []byte) (bool, error)) error {
	keys, vals := kvKeysUnder(s.memKV, prefix)
	for _, k := range keys {
		keep, err := fn(k, vals[k])
		if err != nil {
			return err
		}
		if !keep {
			return nil
		}
	}
	return nil
}

func (s *streamOnlyKV) ScanKeysStream(ctx context.Context, prefix string, fn func(key string) (bool, error)) error {
	keys, _ := kvKeysUnder(s.memKV, prefix)
	for _, k := range keys {
		keep, err := fn(k)
		if err != nil {
			return err
		}
		if !keep {
			return nil
		}
	}
	return nil
}

// bytesOnlyKV exposes ONLY the byte-key scan capability. Its From variant
// skips forward from startKey itself (its inner memKV has no seek
// primitive), exercising the api.KVKeysIter fallback contract while still
// running rangeLookupPKs's byte decoding end to end.
type bytesOnlyKV struct{ *memKV }

var _ api.KVKeysIter = (*bytesOnlyKV)(nil)

func (b *bytesOnlyKV) ScanKeysIter(ctx context.Context, prefix string, fn func(key []byte) (bool, error)) error {
	keys, _ := kvKeysUnder(b.memKV, prefix)
	for _, k := range keys {
		keep, err := fn([]byte(k))
		if err != nil {
			return err
		}
		if !keep {
			return nil
		}
	}
	return nil
}

func (b *bytesOnlyKV) ScanKeysIterFrom(ctx context.Context, prefix, startKey string, fn func(key []byte) (bool, error)) error {
	keys, _ := kvKeysUnder(b.memKV, prefix)
	for _, k := range keys {
		if startKey != "" && k < startKey {
			continue // seek emulation, exactly like kv.Plugin's non-seekable fallback
		}
		keep, err := fn([]byte(k))
		if err != nil {
			return err
		}
		if !keep {
			return nil
		}
	}
	return nil
}

// bufferKV exposes ONLY the BufferKVService capability on top of a fresh
// memKV (Get + copy-into-dst, the documented fallback implementation),
// forcing fetchCandidateRows's GetInto-reuse path: the recycled buffer
// MUST not corrupt retained row values, which is why decodeRowJSON's
// arena contract matters (rows retain copies, never source bytes).
type bufferKV struct{ *memKV }

var _ api.BufferKVService = (*bufferKV)(nil)

func (b *bufferKV) GetInto(ctx context.Context, key string, buf []byte) ([]byte, bool, error) {
	v, hit, err := b.memKV.Get(ctx, key)
	if err != nil || !hit {
		return buf, hit, err
	}
	return append(buf[:0], v...), true, nil
}

// rangeDML builds the same table in any kv: deliberately nasty value
// sets for a range index — a bound-exact value (50), values on both
// sides including negatives and fractions, string values that are
// proper prefixes of each other ("user" sorts before "user-1" with the
// encoded NUL terminator), and a value ("a") that sits below every
// "user*" entry.
func rangeDML() []string {
	return []string{
		"CREATE TABLE bench (id INT PRIMARY KEY, age INT, name TEXT, city TEXT)",
		"INSERT INTO bench (id, age, name, city) VALUES (1, 50, 'user-1', 'praha')",
		"INSERT INTO bench (id, age, name, city) VALUES (2, 49, 'user', 'brno')",
		"INSERT INTO bench (id, age, name, city) VALUES (3, 51, 'user-10', 'ostrava')",
		"INSERT INTO bench (id, age, name, city) VALUES (4, 0, 'user-2', 'praha')",
		"INSERT INTO bench (id, age, name, city) VALUES (5, -3, 'zzz', 'brno')",
		"INSERT INTO bench (id, age, name, city) VALUES (6, 3.25, 'b', 'liberec')",
		"INSERT INTO bench (id, age, name, city) VALUES (7, -0.5, 'user-07', 'ostrava')",
		"INSERT INTO bench (id, age, name, city) VALUES (8, 100, 'a', 'praha')",
		"INSERT INTO bench (id, age, name, city) VALUES (9, 50.5, 'user-11', 'brno')",
		"INSERT INTO bench (id, age, name, city) VALUES (10, 49.9, 'udi', 'ostrava')",
	}
}

// rangeQueryBattery covers every bound shape extractRangeCandidate
// handles: exclusive/inclusive low, high, BETWEEN, numeric and string
// bounds, LIKE prefix, flipped operand order, plus one unextractable
// (OR-shaped) query that must fall back to a full scan on every surface.
var rangeQueryBattery = map[string]string{
	"gt":              "SELECT id FROM bench WHERE age > 50 ORDER BY id",
	"gte":             "SELECT id FROM bench WHERE age >= 50 ORDER BY id",
	"lt":              "SELECT id FROM bench WHERE age < 50 ORDER BY id",
	"lte":             "SELECT id FROM bench WHERE age <= 50 ORDER BY id",
	"between":         "SELECT id FROM bench WHERE age BETWEEN 0 AND 51 ORDER BY id",
	"negLow":          "SELECT id FROM bench WHERE age > -1 ORDER BY id",
	"negHigh":         "SELECT id FROM bench WHERE age < -0.5 ORDER BY id",
	"flipped":         "SELECT id FROM bench WHERE 51 < age ORDER BY id",
	"strGt":           "SELECT id FROM bench WHERE name > 'user-07' ORDER BY id",
	"strGte":          "SELECT id FROM bench WHERE name >= 'user-07' ORDER BY id",
	"strLt":           "SELECT id FROM bench WHERE name < 'user-1' ORDER BY id",
	"likePrefix":      "SELECT id FROM bench WHERE name LIKE 'user-%' ORDER BY id",
	"likeAndBound":    "SELECT id FROM bench WHERE name LIKE 'user-%' AND age <= 50.5 ORDER BY id",
	"orUnextractable": "SELECT id FROM bench WHERE age > 100 OR city = 'praha' ORDER BY id",
}

// TestRangeWalk_ParityAcrossKVSurfaces runs the whole battery against
// three KV surfaces backed by identical data and asserts EXACTLY equal
// result orders. The byte+seek route is the one that could plausibly
// lose results (a wrong seek key would skip matching entries); parity
// against the paged route — which walks everything and decode-filters,
// structurally unable to skip anything — is the strongest available
// ground truth for the seek math.
func TestRangeWalk_ParityAcrossKVSurfaces(t *testing.T) {
	type kvSurface struct {
		name string
		make func() api.KVService
	}
	surfaces := []kvSurface{
		{"paged", func() api.KVService { return newMemKV() }},
		{"stream-string", func() api.KVService { return &streamOnlyKV{newMemKV()} }},
		{"bytes-seek", func() api.KVService { return &bytesOnlyKV{newMemKV()} }},
		{"buffer-getinto", func() api.KVService { return &bufferKV{newMemKV()} }},
	}

	for shape, query := range rangeQueryBattery {
		shape, query := shape, query
		t.Run(shape, func(t *testing.T) {
			var ref []string
			for _, sf := range surfaces {
				e := NewEngine(sf.make())
				for _, stmt := range rangeDML() {
					if _, err := e.Exec(context.Background(), stmt); err != nil {
						t.Fatalf("seed %q: %v", stmt, err)
					}
				}
				rows, err := e.Query(context.Background(), query)
				if err != nil {
					t.Fatalf("%s surface, %q: %v", sf.name, query, err)
				}
				var ids []string
				for _, r := range rows {
					ids = append(ids, fmt.Sprint(r["id"]))
				}
				sort.Strings(ids)
				if ref == nil {
					ref = ids
					continue
				}
				if strings.Join(ids, ",") != strings.Join(ref, ",") {
					t.Fatalf("%s surface results %v != paged-scan reference %v (query %q)",
						sf.name, ids, ref, query)
				}
			}
			if len(ref) == 0 {
				t.Fatalf("battery shape %q matched nothing — the data must hit every shape", shape)
			}
		})
	}
}

// TestDecodeRangeEntry_SuffixFormsAgree checks both entry decoders agree
// on value, pk split, and ok-ness for a battery covering numeric roots
// (zero, negatives, tiny/large magnitudes), strings that are proper
// prefixes of each other (the escaping case), embedded NUL bytes, and
// unicode; plus identically treating undecodable garbage.
func TestDecodeRangeEntry_SuffixFormsAgree(t *testing.T) {
	values := []any{
		float64(0), float64(-1), float64(-12345.678), float64(0.5),
		float64(3.21), float64(1e308), float64(-1e-308), float64(1 << 42),
		"", "a", "user", "user-1", "a b c", "utf-8-ěščř",
		"multi\x00byte\x00string", "trailing-", "-leading", "\x00",
	}
	for _, v := range values {
		var encoded string
		if f, ok := v.(float64); ok {
			encoded = string(rangeTagNumber) + string(encodeSortableFloat(f))
		} else {
			encoded = string(rangeTagString) + string(encodeSortableString(v.(string)))
		}
		suffix := encoded + "pk-0001" // synthetic pk both decoders must split identically

		valS, pkS, okS := decodeRangeEntry(suffix)
		valB, pkB, okB := decodeRangeEntryPrefix([]byte(suffix))
		if !okS || !okB {
			t.Fatalf("value %#v: decodable string=%v byte=%v", v, okS, okB)
		}
		if fmt.Sprint(valS) != fmt.Sprint(valB) {
			t.Fatalf("value %#v: string decode %#v, byte decode %#v", v, valS, valB)
		}
		if fmt.Sprint(valS) != fmt.Sprint(v) {
			t.Fatalf("value round trip changed: %v -> %v", v, valS)
		}
		if pkS != pkB || pkS != "pk-0001" {
			t.Fatalf("value %#v: pk split wrong: string %q byte %q", v, pkS, pkB)
		}
	}

	for _, bad := range []string{"", "x", "n", "s", "nabc", "s\x01\x02"} {
		if _, _, ok := decodeRangeEntry(bad); ok {
			t.Fatalf("decodeRangeEntry(%q): unexpectedly decodable", bad)
		}
		if _, _, ok := decodeRangeEntryPrefix([]byte(bad)); ok {
			t.Fatalf("decodeRangeEntryPrefix(%q): unexpectedly decodable", bad)
		}
	}
}
