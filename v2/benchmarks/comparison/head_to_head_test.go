package comparison

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"testing"
)

// factory constructs one KVEngine rooted at dir. Each benchmark iteration
// (or sub-benchmark run) gets its own fresh dir via b.TempDir(), so
// engines never share on-disk state across factories or runs.
type factory struct {
	name string
	new  func(dir string) (KVEngine, error)
}

// Postgres and MySQL are deliberately not included here: both require a
// running server process, which isn't something `go test -bench` can
// reproducibly start on an arbitrary machine. Velocity, SQLite, and
// BoltDB are all embedded, in-process, file-backed engines, which is
// what makes this specific three-way comparison apples-to-apples.
var factories = []factory{
	{"velocity", func(dir string) (KVEngine, error) { return NewVelocityEngine(dir) }},
	// velocity-fast uses fsync_mode: "posix" — SQLite's own actual
	// durability level (plain fsync(2), survives process/OS crashes, not a
	// real power interruption), instead of velocity's stronger default
	// (fcntl(F_FULLFSYNC) on Darwin, real power-loss survival). Included
	// specifically to make the SQLite comparison apples-to-apples on
	// durability — see plugins/storage-lsm's FsyncMode doc comment.
	{"velocity-fast", func(dir string) (KVEngine, error) { return NewVelocityEngineFast(dir) }},
	{"sqlite", func(dir string) (KVEngine, error) { return NewSQLiteEngine(filepath.Join(dir, "bench.db")) }},
	{"boltdb", func(dir string) (KVEngine, error) { return NewBoltEngine(filepath.Join(dir, "bench.bolt")) }},
}

// fixedKV deterministically (seeded) generates n key/value pairs of the
// given value size, identical across every factory's benchmark run so
// the comparison is fair.
func fixedKV(n, valueSize int) [][2][]byte {
	r := rand.New(rand.NewSource(42))
	out := make([][2][]byte, n)
	for i := range n {
		k := fmt.Appendf(nil, "key-%08d", i)
		v := make([]byte, valueSize)
		r.Read(v)
		out[i] = [2][]byte{k, v}
	}
	return out
}

// BenchmarkPut measures per-Put cost (each Put is its own fsync'd commit
// on every engine here) against a 10,000-key/128-byte-value working set.
func BenchmarkPut(b *testing.B) {
	data := fixedKV(10000, 128)
	for _, f := range factories {
		b.Run(f.name, func(b *testing.B) {
			eng, err := f.new(b.TempDir())
			if err != nil {
				b.Fatalf("new %s: %v", f.name, err)
			}
			defer eng.Close()

			b.ReportAllocs()
			b.ResetTimer()
			i := 0
			for b.Loop() {
				kv := data[i%len(data)]
				if err := eng.Put(kv[0], kv[1]); err != nil {
					b.Fatalf("put: %v", err)
				}
				i++
			}
		})
	}
}

// BenchmarkGet measures random-key point-lookup cost against the same
// pre-populated 10,000-key working set every engine seeds identically.
func BenchmarkGet(b *testing.B) {
	data := fixedKV(10000, 128)
	for _, f := range factories {
		b.Run(f.name, func(b *testing.B) {
			eng, err := f.new(b.TempDir())
			if err != nil {
				b.Fatalf("new %s: %v", f.name, err)
			}
			defer eng.Close()
			for _, kv := range data {
				if err := eng.Put(kv[0], kv[1]); err != nil {
					b.Fatalf("seed put: %v", err)
				}
			}

			r := rand.New(rand.NewSource(1))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				kv := data[r.Intn(len(data))]
				if _, ok, err := eng.Get(kv[0]); err != nil || !ok {
					b.Fatalf("get: ok=%v err=%v", ok, err)
				}
			}
		})
	}
}

// BenchmarkSequentialWriteBatch measures the wall-clock cost of writing a
// fixed 5,000-key batch sequentially into a fresh engine instance per
// iteration — a "cold start, load N records" scenario, distinct from
// BenchmarkPut's steady-state per-op cost.
func BenchmarkSequentialWriteBatch(b *testing.B) {
	const n = 5000
	data := fixedKV(n, 128)
	for _, f := range factories {
		b.Run(f.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				dir := b.TempDir()
				eng, err := f.new(dir)
				if err != nil {
					b.Fatalf("new %s: %v", f.name, err)
				}
				for _, kv := range data {
					if err := eng.Put(kv[0], kv[1]); err != nil {
						b.Fatalf("put: %v", err)
					}
				}
				eng.Close()
			}
		})
	}
}
