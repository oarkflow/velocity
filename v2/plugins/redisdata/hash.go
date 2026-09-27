package redisdata

import (
	"context"

	"github.com/oarkflow/velocity/v2/api"
)

// Hash on-disk layout: redisdata/hash/<key>/field/<field> -> value.
// HSet/HGet/HDel are direct O(1) point operations; HGetAll/HLen are
// O(field count) prefix scans.

func hashFieldKey(key, field string) []byte {
	return []byte("redisdata/hash/" + key + "/field/" + field)
}

func hashPrefix(key string) []byte {
	return []byte("redisdata/hash/" + key + "/field/")
}

func (p *Plugin) HSet(ctx context.Context, key, field string, value []byte) error {
	return p.storage.Put(ctx, api.Entry{Key: hashFieldKey(key, field), Value: value})
}

func (p *Plugin) HGet(ctx context.Context, key, field string) ([]byte, bool, error) {
	return p.storage.Get(ctx, hashFieldKey(key, field))
}

func (p *Plugin) HDel(ctx context.Context, key, field string) error {
	return p.storage.Delete(ctx, hashFieldKey(key, field))
}

func (p *Plugin) HGetAll(ctx context.Context, key string) (map[string][]byte, error) {
	it, err := p.storage.Scan(ctx, hashPrefix(key))
	if err != nil {
		return nil, err
	}
	defer it.Close()

	prefixLen := len(hashPrefix(key))
	out := make(map[string][]byte)
	for it.Next() {
		full := it.Key()
		field := string(full[prefixLen:])
		v := make([]byte, len(it.Value()))
		copy(v, it.Value())
		out[field] = v
	}
	return out, it.Err()
}

func (p *Plugin) HLen(ctx context.Context, key string) (int64, error) {
	it, err := p.storage.Scan(ctx, hashPrefix(key))
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
