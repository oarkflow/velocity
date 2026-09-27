package redisdata

import (
	"context"

	"github.com/oarkflow/velocity/v2/api"
)

// Set on-disk layout: redisdata/set/<key>/member/<member-bytes> ->
// presence marker (a single 0x01 byte). SAdd/SRem/SIsMember are direct
// O(1) point operations; SMembers/SCard are O(cardinality) prefix scans.
// Storing the raw member bytes in the key (rather than a hash of them)
// means SMembers can recover the exact original bytes without a separate
// value lookup or reverse index.

func setMemberKey(key string, member []byte) []byte {
	return append([]byte("redisdata/set/"+key+"/member/"), member...)
}

func setPrefix(key string) []byte {
	return []byte("redisdata/set/" + key + "/member/")
}

func (p *Plugin) SAdd(ctx context.Context, key string, members ...[]byte) (int64, error) {
	var added int64
	for _, m := range members {
		k := setMemberKey(key, m)
		_, ok, err := p.storage.Get(ctx, k)
		if err != nil {
			return added, err
		}
		if ok {
			continue
		}
		if err := p.storage.Put(ctx, api.Entry{Key: k, Value: []byte{1}}); err != nil {
			return added, err
		}
		added++
	}
	return added, nil
}

func (p *Plugin) SRem(ctx context.Context, key string, members ...[]byte) (int64, error) {
	var removed int64
	for _, m := range members {
		k := setMemberKey(key, m)
		_, ok, err := p.storage.Get(ctx, k)
		if err != nil {
			return removed, err
		}
		if !ok {
			continue
		}
		if err := p.storage.Delete(ctx, k); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func (p *Plugin) SMembers(ctx context.Context, key string) ([][]byte, error) {
	it, err := p.storage.Scan(ctx, setPrefix(key))
	if err != nil {
		return nil, err
	}
	defer it.Close()

	prefixLen := len(setPrefix(key))
	out := [][]byte{}
	for it.Next() {
		full := it.Key()
		member := make([]byte, len(full)-prefixLen)
		copy(member, full[prefixLen:])
		out = append(out, member)
	}
	return out, it.Err()
}

func (p *Plugin) SIsMember(ctx context.Context, key string, member []byte) (bool, error) {
	_, ok, err := p.storage.Get(ctx, setMemberKey(key, member))
	return ok, err
}

func (p *Plugin) SCard(ctx context.Context, key string) (int64, error) {
	it, err := p.storage.Scan(ctx, setPrefix(key))
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
