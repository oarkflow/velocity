package velocity

import (
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestLRUCacheBasic(t *testing.T) {
	c := NewLRUCache(1024) // 1KB

	c.Put("a", []byte("hello"))
	if v, ok := c.Get("a"); !ok || string(v) != "hello" {
		t.Fatalf("expected hello, got %v", v)
	}

	// Insert until eviction
	for i := 0; i < 100; i++ {
		k := fmt.Sprintf("%c%d", 'a'+(i%26), i)
		c.Put(k, make([]byte, 100))
	}

	// ensure total bytes <= capacity
	if c.totalBytes > c.capacityBytes {
		t.Fatalf("cache exceeded capacity: %d > %d", c.totalBytes, c.capacityBytes)
	}
}

func BenchmarkLRUCache(b *testing.B) {
	c := NewLRUCache(20 * 1024 * 1024) // 20MB
	b.ReportAllocs()

	keys := make([]string, 100000)
	for i := range keys {
		keys[i] = fmt.Sprintf("%d", rand.Int63())
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		for pb.Next() {
			i := r.Intn(len(keys))
			k := keys[i]
			c.Put(k, make([]byte, 100))
			c.Get(k)
		}
	})
}

func BenchmarkLRUCacheConcurrent(b *testing.B) {
	c := NewLRUCache(20 * 1024 * 1024) // 20MB
	b.ReportAllocs()

	var wg sync.WaitGroup
	n := runtime.NumCPU()
	ops := 100000

	b.ResetTimer()
	for w := 0; w < n; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := rand.New(rand.NewSource(time.Now().UnixNano()))
			for i := 0; i < ops; i++ {
				k := fmt.Sprintf("%d", r.Int63())
				c.Put(k, make([]byte, 128))
				c.Get(k)
			}
		}()
	}
	wg.Wait()
}
