package redisdata

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/oarkflow/velocity/v2/api"
)

// SortedSet on-disk layout:
//
//	redisdata/zset/<key>/lookup/<member>              -> score (8 bytes, raw float64 bits)
//	redisdata/zset/<key>/byscore/<sortable-score><len><member> -> score (8 bytes, raw float64 bits)
//
// The lookup index gives O(1) ZScore/ZRem (both need to know a member's
// current score — ZRem to find and delete its byscore entry, ZScore to
// answer directly). The byscore index gives ordered iteration for ZRange
// via a prefix Scan in ascending key order, which is ascending score
// order because the score is encoded as a byte sequence whose
// lexicographic order matches its numeric order (sortableFloatBytes,
// below) — the standard IEEE-754-bits-with-sign-handling trick. Ties
// (equal scores) are broken by member byte order, matching real Redis's
// own tie-breaking rule.
//
// ZRange collects the ENTIRE ordered set via one Scan before applying
// Redis-style start/stop index normalization — O(cardinality), not
// O(range size). A production system wanting O(range size) ZRange would
// need a backend that supports seeking to an arbitrary scan start point
// by byte offset rather than only by prefix; documented here as a known
// scaling limitation, not hidden.
//
// zsetMu (see plugin.go) makes ZAdd's read-old-score-then-write sequence
// atomic across concurrent callers on any key in this plugin instance.

func zsetLookupKey(key, member string) []byte {
	return []byte("redisdata/zset/" + key + "/lookup/" + member)
}

func zsetByScorePrefix(key string) []byte {
	return []byte("redisdata/zset/" + key + "/byscore/")
}

// sortableFloatBytes maps a float64 to an 8-byte big-endian sequence whose
// byte-lexicographic order matches the float's numeric order (including
// across the negative/zero/positive boundary): for non-negative floats,
// set the sign bit (pushing them above all negatives); for negative
// floats, flip every bit (reversing their internal descending-by-bits
// order into ascending, and placing them below all non-negatives).
func sortableFloatBytes(f float64) []byte {
	bits := math.Float64bits(f)
	if bits&(1<<63) != 0 {
		bits = ^bits
	} else {
		bits |= 1 << 63
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, bits)
	return b
}

func zsetByScoreKey(key string, score float64, member []byte) []byte {
	prefix := zsetByScorePrefix(key)
	out := make([]byte, 0, len(prefix)+8+4+len(member))
	out = append(out, prefix...)
	out = append(out, sortableFloatBytes(score)...)
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(member)))
	out = append(out, lenBuf...)
	out = append(out, member...)
	return out
}

func encodeScore(score float64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, math.Float64bits(score))
	return b
}

func decodeScore(v []byte) (float64, error) {
	if len(v) != 8 {
		return 0, fmt.Errorf("redisdata: corrupt zset score encoding (want 8 bytes, got %d)", len(v))
	}
	return math.Float64frombits(binary.BigEndian.Uint64(v)), nil
}

// extractMemberFromByScoreKey parses a full byscore key (as returned by
// Iterator.Key()) back into its member bytes, given the key prefix it was
// stored under.
func extractMemberFromByScoreKey(full []byte, prefix []byte) ([]byte, error) {
	rest := full[len(prefix):]
	if len(rest) < 8+4 {
		return nil, fmt.Errorf("redisdata: corrupt zset byscore key (too short)")
	}
	memberLen := binary.BigEndian.Uint32(rest[8:12])
	rest = rest[12:]
	if uint32(len(rest)) != memberLen {
		return nil, fmt.Errorf("redisdata: corrupt zset byscore key (length mismatch)")
	}
	member := make([]byte, len(rest))
	copy(member, rest)
	return member, nil
}

func (p *Plugin) ZAdd(ctx context.Context, key string, score float64, member []byte) error {
	p.zsetMu.Lock()
	defer p.zsetMu.Unlock()

	lookupKey := zsetLookupKey(key, string(member))
	if old, ok, err := p.storage.Get(ctx, lookupKey); err != nil {
		return err
	} else if ok {
		oldScore, err := decodeScore(old)
		if err != nil {
			return err
		}
		if oldScore == score {
			// No change; still ensure the entry is present (idempotent).
			return p.storage.Put(ctx, api.Entry{Key: lookupKey, Value: encodeScore(score)})
		}
		if err := p.storage.Delete(ctx, zsetByScoreKey(key, oldScore, member)); err != nil {
			return err
		}
	}

	if err := p.storage.Put(ctx, api.Entry{Key: lookupKey, Value: encodeScore(score)}); err != nil {
		return err
	}
	return p.storage.Put(ctx, api.Entry{Key: zsetByScoreKey(key, score, member), Value: encodeScore(score)})
}

func (p *Plugin) ZScore(ctx context.Context, key string, member []byte) (float64, bool, error) {
	v, ok, err := p.storage.Get(ctx, zsetLookupKey(key, string(member)))
	if err != nil || !ok {
		return 0, ok, err
	}
	score, err := decodeScore(v)
	return score, true, err
}

func (p *Plugin) ZRem(ctx context.Context, key string, member []byte) error {
	p.zsetMu.Lock()
	defer p.zsetMu.Unlock()

	lookupKey := zsetLookupKey(key, string(member))
	v, ok, err := p.storage.Get(ctx, lookupKey)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	score, err := decodeScore(v)
	if err != nil {
		return err
	}
	if err := p.storage.Delete(ctx, lookupKey); err != nil {
		return err
	}
	return p.storage.Delete(ctx, zsetByScoreKey(key, score, member))
}

func (p *Plugin) ZCard(ctx context.Context, key string) (int64, error) {
	it, err := p.storage.Scan(ctx, zsetByScorePrefix(key))
	if err != nil {
		return 0, err
	}
	defer it.Close()
	var n int64
	for it.Next() {
		n++
	}
	return n, it.Err()
}

// ZRange follows Redis semantics: ascending score order, 0-based
// inclusive start/stop, negative indices count from the end.
func (p *Plugin) ZRange(ctx context.Context, key string, start, stop int64) ([][]byte, error) {
	prefix := zsetByScorePrefix(key)
	it, err := p.storage.Scan(ctx, prefix)
	if err != nil {
		return nil, err
	}
	defer it.Close()

	var members [][]byte
	for it.Next() {
		m, err := extractMemberFromByScoreKey(it.Key(), prefix)
		if err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	if err := it.Err(); err != nil {
		return nil, err
	}

	length := int64(len(members))
	if length == 0 {
		return [][]byte{}, nil
	}
	if start < 0 {
		start = length + start
	}
	if stop < 0 {
		stop = length + stop
	}
	if start < 0 {
		start = 0
	}
	if stop >= length {
		stop = length - 1
	}
	if start > stop || start >= length {
		return [][]byte{}, nil
	}
	return members[start : stop+1], nil
}
