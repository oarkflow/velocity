package resp

import (
	"context"
	"path"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// memKV is a minimal in-test api.KVService, used so this package's tests
// don't depend on the real plugins/kv package (avoiding an import cycle
// risk and keeping this package's tests self-contained, matching the
// convention used by other plugin tests in this codebase).
type memKV struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemKV() *memKV { return &memKV{data: make(map[string][]byte)} }

func (m *memKV) Put(ctx context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = append([]byte(nil), value...)
	return nil
}

func (m *memKV) PutWithTTL(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return m.Put(ctx, key, value)
}

func (m *memKV) Get(ctx context.Context, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	return v, ok, nil
}

func (m *memKV) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *memKV) Exists(ctx context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.data[key]
	return ok, nil
}

func (m *memKV) Incr(ctx context.Context, key string, delta int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	if v, ok := m.data[key]; ok {
		for _, b := range v {
			n = n*10 + int64(b-'0')
		}
	}
	n += delta
	m.data[key] = []byte(itoa(n))
	return n, nil
}

func itoa(n int64) string {
	neg := n < 0
	if neg {
		n = -n
	}
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func (m *memKV) Keys(ctx context.Context, pattern string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.data {
		if ok, _ := path.Match(pattern, k); ok {
			out = append(out, k)
		}
	}
	return out, nil
}

func (m *memKV) Scan(ctx context.Context, prefix string, limit int, cursor string) (map[string][]byte, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string][]byte{}
	for k, v := range m.data {
		if len(out) >= limit {
			break
		}
		out[k] = v
	}
	return out, "", nil
}

var _ api.KVService = (*memKV)(nil)

// memPubSub is a minimal in-test api.PubSubService.
type memPubSub struct {
	mu   sync.Mutex
	subs map[string]map[int]chan api.PubSubMessage
	next int
}

func newMemPubSub() *memPubSub {
	return &memPubSub{subs: make(map[string]map[int]chan api.PubSubMessage)}
}

func (m *memPubSub) Publish(ctx context.Context, channel string, payload []byte) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	subs := m.subs[channel]
	var n int64
	for _, ch := range subs {
		select {
		case ch <- api.PubSubMessage{Channel: channel, Payload: payload}:
			n++
		default:
		}
	}
	return n, nil
}

func (m *memPubSub) Subscribe(ctx context.Context, channel string) (<-chan api.PubSubMessage, func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.subs[channel] == nil {
		m.subs[channel] = make(map[int]chan api.PubSubMessage)
	}
	id := m.next
	m.next++
	ch := make(chan api.PubSubMessage, 8)
	m.subs[channel][id] = ch
	cancel := func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if subs, ok := m.subs[channel]; ok {
			delete(subs, id)
		}
		close(ch)
	}
	return ch, cancel, nil
}

var _ api.PubSubService = (*memPubSub)(nil)

// memList/memSet/memHash/memZSet: minimal in-test implementations of the
// remaining data-structure interfaces, so this package's tests can
// exercise LPUSH/SADD/HSET/ZADD-family commands without depending on the
// (separately built) plugins/redisdata package.

type memList struct {
	mu   sync.Mutex
	data map[string][][]byte
}

func newMemList() *memList { return &memList{data: make(map[string][][]byte)} }

func (m *memList) LPush(ctx context.Context, key string, values ...[]byte) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range values {
		m.data[key] = append([][]byte{v}, m.data[key]...)
	}
	return int64(len(m.data[key])), nil
}

func (m *memList) RPush(ctx context.Context, key string, values ...[]byte) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = append(m.data[key], values...)
	return int64(len(m.data[key])), nil
}

func (m *memList) LPop(ctx context.Context, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.data[key]
	if len(l) == 0 {
		return nil, false, nil
	}
	v := l[0]
	m.data[key] = l[1:]
	return v, true, nil
}

func (m *memList) RPop(ctx context.Context, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.data[key]
	if len(l) == 0 {
		return nil, false, nil
	}
	v := l[len(l)-1]
	m.data[key] = l[:len(l)-1]
	return v, true, nil
}

func normIdx(i, n int64) int64 {
	if i < 0 {
		i = n + i
	}
	if i < 0 {
		i = 0
	}
	return i
}

func (m *memList) LRange(ctx context.Context, key string, start, stop int64) ([][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.data[key]
	n := int64(len(l))
	if n == 0 {
		return nil, nil
	}
	s := normIdx(start, n)
	e := normIdx(stop, n)
	if e >= n {
		e = n - 1
	}
	if s > e || s >= n {
		return nil, nil
	}
	out := make([][]byte, 0, e-s+1)
	for i := s; i <= e; i++ {
		out = append(out, l[i])
	}
	return out, nil
}

func (m *memList) LLen(ctx context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return int64(len(m.data[key])), nil
}

var _ api.ListService = (*memList)(nil)

type memSet struct {
	mu   sync.Mutex
	data map[string]map[string][]byte
}

func newMemSet() *memSet { return &memSet{data: make(map[string]map[string][]byte)} }

func (m *memSet) SAdd(ctx context.Context, key string, members ...[]byte) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data[key] == nil {
		m.data[key] = make(map[string][]byte)
	}
	var added int64
	for _, mem := range members {
		k := string(mem)
		if _, ok := m.data[key][k]; !ok {
			added++
		}
		m.data[key][k] = mem
	}
	return added, nil
}

func (m *memSet) SRem(ctx context.Context, key string, members ...[]byte) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var removed int64
	for _, mem := range members {
		k := string(mem)
		if _, ok := m.data[key][k]; ok {
			delete(m.data[key], k)
			removed++
		}
	}
	return removed, nil
}

func (m *memSet) SMembers(ctx context.Context, key string) ([][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]byte, 0, len(m.data[key]))
	for _, v := range m.data[key] {
		out = append(out, v)
	}
	return out, nil
}

func (m *memSet) SIsMember(ctx context.Context, key string, member []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.data[key][string(member)]
	return ok, nil
}

func (m *memSet) SCard(ctx context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return int64(len(m.data[key])), nil
}

var _ api.SetService = (*memSet)(nil)

type memHash struct {
	mu   sync.Mutex
	data map[string]map[string][]byte
}

func newMemHash() *memHash { return &memHash{data: make(map[string]map[string][]byte)} }

func (m *memHash) HSet(ctx context.Context, key, field string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data[key] == nil {
		m.data[key] = make(map[string][]byte)
	}
	m.data[key][field] = value
	return nil
}

func (m *memHash) HGet(ctx context.Context, key, field string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key][field]
	return v, ok, nil
}

func (m *memHash) HDel(ctx context.Context, key, field string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data[key], field)
	return nil
}

func (m *memHash) HGetAll(ctx context.Context, key string) (map[string][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string][]byte, len(m.data[key]))
	for k, v := range m.data[key] {
		out[k] = v
	}
	return out, nil
}

func (m *memHash) HLen(ctx context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return int64(len(m.data[key])), nil
}

var _ api.HashService = (*memHash)(nil)

type zmember struct {
	member []byte
	score  float64
}

type memZSet struct {
	mu   sync.Mutex
	data map[string][]zmember
}

func newMemZSet() *memZSet { return &memZSet{data: make(map[string][]zmember)} }

func (m *memZSet) ZAdd(ctx context.Context, key string, score float64, member []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.data[key]
	for i, zm := range list {
		if string(zm.member) == string(member) {
			list[i].score = score
			m.resort(key)
			return nil
		}
	}
	m.data[key] = append(list, zmember{member: member, score: score})
	m.resort(key)
	return nil
}

func (m *memZSet) resort(key string) {
	list := m.data[key]
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j-1].score > list[j].score; j-- {
			list[j-1], list[j] = list[j], list[j-1]
		}
	}
}

func (m *memZSet) ZRange(ctx context.Context, key string, start, stop int64) ([][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.data[key]
	n := int64(len(list))
	if n == 0 {
		return nil, nil
	}
	s := normIdx(start, n)
	e := normIdx(stop, n)
	if e >= n {
		e = n - 1
	}
	if s > e || s >= n {
		return nil, nil
	}
	out := make([][]byte, 0, e-s+1)
	for i := s; i <= e; i++ {
		out = append(out, list[i].member)
	}
	return out, nil
}

func (m *memZSet) ZScore(ctx context.Context, key string, member []byte) (float64, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, zm := range m.data[key] {
		if string(zm.member) == string(member) {
			return zm.score, true, nil
		}
	}
	return 0, false, nil
}

func (m *memZSet) ZRem(ctx context.Context, key string, member []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.data[key]
	for i, zm := range list {
		if string(zm.member) == string(member) {
			m.data[key] = append(list[:i], list[i+1:]...)
			return nil
		}
	}
	return nil
}

func (m *memZSet) ZCard(ctx context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return int64(len(m.data[key])), nil
}

var _ api.SortedSetService = (*memZSet)(nil)
