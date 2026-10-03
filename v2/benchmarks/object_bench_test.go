package benchmarks

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/oarkflow/velocity/v2/api"
)

func benchObjectPut(b *testing.B, size int) {
	svc, cleanup := bootObject(b)
	defer cleanup()
	benchObjectPutWith(b, svc, size)
}

// benchObjectPutFsync is benchObjectPut with an explicit fsync mode,
// isolating the per-PutObject durable-commit cost (Object Put batches
// metadata + every block into ONE storage Batch, and a Batch is always
// durable — so fsync_mode is the entire durability/performance knob).
func benchObjectPutFsync(b *testing.B, size int, fsyncMode string) {
	svc, cleanup := bootObjectFsync(b, fsyncMode)
	defer cleanup()
	benchObjectPutWith(b, svc, size)
}

func benchObjectPutWith(b *testing.B, svc api.ObjectService, size int) {
	ctx := context.Background()
	if err := svc.CreateBucket(ctx, "bench"); err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), size)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("obj-%d", i)
		if _, err := svc.PutObject(ctx, "bench", key, bytes.NewReader(payload), api.ObjectMeta{ContentType: "application/octet-stream"}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkObjectPut_1KB(b *testing.B)  { benchObjectPut(b, 1<<10) }
func BenchmarkObjectPut_64KB(b *testing.B) { benchObjectPut(b, 64<<10) }
func BenchmarkObjectPut_1MB(b *testing.B)  { benchObjectPut(b, 1<<20) }

// _fast variants use fsync_mode: "posix" (SQLite-equivalent durability:
// survives process/OS crash, not power loss) instead of the default
// "full" (F_FULLFSYNC on Darwin) — the same split the KV comparison
// benchmarks use, so the fsync-mode cost is visible rather than hidden
// inside "object overhead".
func BenchmarkObjectPut_1KB_fast(b *testing.B) { benchObjectPutFsync(b, 1<<10, "posix") }
func BenchmarkObjectPut_1MB_fast(b *testing.B) { benchObjectPutFsync(b, 1<<20, "posix") }

func benchObjectGet(b *testing.B, size int) {
	svc, cleanup := bootObject(b)
	defer cleanup()
	ctx := context.Background()
	if err := svc.CreateBucket(ctx, "bench"); err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), size)
	const n = 100
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("obj-%d", i)
		if _, err := svc.PutObject(ctx, "bench", key, bytes.NewReader(payload), api.ObjectMeta{ContentType: "application/octet-stream"}); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("obj-%d", i%n)
		r, _, err := svc.GetObject(ctx, "bench", key, "")
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, r); err != nil {
			b.Fatal(err)
		}
		r.Close()
	}
}

func BenchmarkObjectGet_1KB(b *testing.B)  { benchObjectGet(b, 1<<10) }
func BenchmarkObjectGet_64KB(b *testing.B) { benchObjectGet(b, 64<<10) }
func BenchmarkObjectGet_1MB(b *testing.B)  { benchObjectGet(b, 1<<20) }

func BenchmarkObjectList(b *testing.B) {
	svc, cleanup := bootObject(b)
	defer cleanup()
	ctx := context.Background()
	if err := svc.CreateBucket(ctx, "bench"); err != nil {
		b.Fatal(err)
	}
	const n = 1000
	payload := []byte("x")
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("list/obj-%05d", i)
		if _, err := svc.PutObject(ctx, "bench", key, bytes.NewReader(payload), api.ObjectMeta{}); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.ListObjects(ctx, "bench", "list/"); err != nil {
			b.Fatal(err)
		}
	}
}
