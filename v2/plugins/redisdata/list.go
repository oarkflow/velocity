package redisdata

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/oarkflow/velocity/v2/api"
)

// List on-disk layout:
//
//	redisdata/list/<key>/meta          -> "<head>:<tail>" (decimal int64s)
//	redisdata/list/<key>/elem/<index>  -> element bytes, index a decimal
//	                                       (possibly negative) int64 string
//
// head/tail are logical indices into an unbounded integer line, not
// array positions — LPush decrements head and stores at the new head;
// RPush increments tail and stores at the new tail. An empty list is
// represented by head > tail (or no meta key at all). Because the index
// space is unbounded in both directions, LPush/RPush/LPop/RPop never need
// to shift existing elements: each is exactly one meta update plus one
// element read/write, O(1) in the number of StorageBackend operations
// regardless of list length. LRange(start, stop) computes which absolute
// indices [head+start, head+stop] are needed after Redis-style negative
// index normalization, then reads exactly that many elements directly by
// key — O(range size), not O(list length).
//
// listMu (see plugin.go) serializes all mutations across all lists in
// this plugin instance; a production system with many hot, independent
// lists would want to shard this by key, documented as a known
// concurrency-granularity tradeoff, not a correctness gap.

func listMetaKey(key string) []byte { return []byte("redisdata/list/" + key + "/meta") }

func listElemKey(key string, idx int64) []byte {
	return []byte("redisdata/list/" + key + "/elem/" + strconv.FormatInt(idx, 10))
}

// loadListMeta returns (head, tail, exists). A non-existent meta key means
// an empty list; by convention we report head=0, tail=-1 (length 0).
func (p *Plugin) loadListMeta(ctx context.Context, key string) (head, tail int64, err error) {
	v, ok, err := p.storage.Get(ctx, listMetaKey(key))
	if err != nil {
		return 0, 0, err
	}
	if !ok {
		return 0, -1, nil
	}
	parts := strings.SplitN(string(v), ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("redisdata: corrupt list meta for %q", key)
	}
	head, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("redisdata: corrupt list meta for %q: %w", key, err)
	}
	tail, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("redisdata: corrupt list meta for %q: %w", key, err)
	}
	return head, tail, nil
}

func (p *Plugin) saveListMeta(ctx context.Context, key string, head, tail int64) error {
	if head > tail {
		// Empty: remove the meta key entirely rather than persist an
		// empty-but-present marker, so an untouched/fully-drained list
		// looks identical to one that was never created.
		return p.storage.Delete(ctx, listMetaKey(key))
	}
	v := strconv.FormatInt(head, 10) + ":" + strconv.FormatInt(tail, 10)
	return p.storage.Put(ctx, api.Entry{Key: listMetaKey(key), Value: []byte(v)})
}

func (p *Plugin) LPush(ctx context.Context, key string, values ...[]byte) (int64, error) {
	p.listMu.Lock()
	defer p.listMu.Unlock()

	head, tail, err := p.loadListMeta(ctx, key)
	if err != nil {
		return 0, err
	}
	// Redis LPUSH k v1 v2 v3 ends with v3 as the new head, v2 next, v1
	// next, then the old head — i.e. each successive value is pushed to
	// the (now further left) head in turn.
	for _, v := range values {
		head--
		if err := p.storage.Put(ctx, api.Entry{Key: listElemKey(key, head), Value: v}); err != nil {
			return 0, err
		}
	}
	if err := p.saveListMeta(ctx, key, head, tail); err != nil {
		return 0, err
	}
	return tail - head + 1, nil
}

func (p *Plugin) RPush(ctx context.Context, key string, values ...[]byte) (int64, error) {
	p.listMu.Lock()
	defer p.listMu.Unlock()

	head, tail, err := p.loadListMeta(ctx, key)
	if err != nil {
		return 0, err
	}
	for _, v := range values {
		tail++
		if err := p.storage.Put(ctx, api.Entry{Key: listElemKey(key, tail), Value: v}); err != nil {
			return 0, err
		}
	}
	if err := p.saveListMeta(ctx, key, head, tail); err != nil {
		return 0, err
	}
	return tail - head + 1, nil
}

func (p *Plugin) LPop(ctx context.Context, key string) ([]byte, bool, error) {
	p.listMu.Lock()
	defer p.listMu.Unlock()

	head, tail, err := p.loadListMeta(ctx, key)
	if err != nil {
		return nil, false, err
	}
	if head > tail {
		return nil, false, nil
	}
	v, ok, err := p.storage.Get(ctx, listElemKey(key, head))
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, fmt.Errorf("redisdata: list %q meta/element inconsistency at head %d", key, head)
	}
	if err := p.storage.Delete(ctx, listElemKey(key, head)); err != nil {
		return nil, false, err
	}
	head++
	if err := p.saveListMeta(ctx, key, head, tail); err != nil {
		return nil, false, err
	}
	return v, true, nil
}

func (p *Plugin) RPop(ctx context.Context, key string) ([]byte, bool, error) {
	p.listMu.Lock()
	defer p.listMu.Unlock()

	head, tail, err := p.loadListMeta(ctx, key)
	if err != nil {
		return nil, false, err
	}
	if head > tail {
		return nil, false, nil
	}
	v, ok, err := p.storage.Get(ctx, listElemKey(key, tail))
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, fmt.Errorf("redisdata: list %q meta/element inconsistency at tail %d", key, tail)
	}
	if err := p.storage.Delete(ctx, listElemKey(key, tail)); err != nil {
		return nil, false, err
	}
	tail--
	if err := p.saveListMeta(ctx, key, head, tail); err != nil {
		return nil, false, err
	}
	return v, true, nil
}

func (p *Plugin) LLen(ctx context.Context, key string) (int64, error) {
	p.listMu.Lock()
	defer p.listMu.Unlock()
	head, tail, err := p.loadListMeta(ctx, key)
	if err != nil {
		return 0, err
	}
	if head > tail {
		return 0, nil
	}
	return tail - head + 1, nil
}

// LRange follows Redis semantics exactly: 0-based, inclusive, negative
// indices count from the end (-1 is the last element). Out-of-range
// indices are clamped rather than erroring, and an empty or fully
// out-of-range request returns an empty (non-nil) slice.
func (p *Plugin) LRange(ctx context.Context, key string, start, stop int64) ([][]byte, error) {
	p.listMu.Lock()
	head, tail, err := p.loadListMeta(ctx, key)
	p.listMu.Unlock()
	if err != nil {
		return nil, err
	}
	length := int64(0)
	if head <= tail {
		length = tail - head + 1
	}
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

	out := make([][]byte, 0, stop-start+1)
	for i := head + start; i <= head+stop; i++ {
		v, ok, err := p.storage.Get(ctx, listElemKey(key, i))
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("redisdata: list %q meta/element inconsistency at index %d", key, i)
		}
		out = append(out, v)
	}
	return out, nil
}
