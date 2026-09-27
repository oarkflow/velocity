package benchmarks

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
)

func benchKVPut(b *testing.B, storageName string) {
	svc, cleanup := bootKV(b, storageName)
	defer cleanup()
	ctx := context.Background()
	val := make([]byte, 128)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := svc.Put(ctx, fmt.Sprintf("key-%d", i), val); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKVPut_StorageLSM(b *testing.B) { benchKVPut(b, "storage-lsm") }
func BenchmarkKVPut_StorageMem(b *testing.B) { benchKVPut(b, "storage-mem") }

func benchKVGet(b *testing.B, storageName string) {
	svc, cleanup := bootKV(b, storageName)
	defer cleanup()
	ctx := context.Background()
	const n = 10000
	val := make([]byte, 128)
	for i := 0; i < n; i++ {
		if err := svc.Put(ctx, fmt.Sprintf("key-%d", i), val); err != nil {
			b.Fatal(err)
		}
	}
	r := rand.New(rand.NewSource(1))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k := fmt.Sprintf("key-%d", r.Intn(n))
		if _, _, err := svc.Get(ctx, k); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKVGet_StorageLSM(b *testing.B) { benchKVGet(b, "storage-lsm") }
func BenchmarkKVGet_StorageMem(b *testing.B) { benchKVGet(b, "storage-mem") }

func benchKVDelete(b *testing.B, storageName string) {
	svc, cleanup := bootKV(b, storageName)
	defer cleanup()
	ctx := context.Background()
	val := make([]byte, 128)
	for i := 0; i < b.N; i++ {
		if err := svc.Put(ctx, fmt.Sprintf("del-%d", i), val); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := svc.Delete(ctx, fmt.Sprintf("del-%d", i)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKVDelete_StorageLSM(b *testing.B) { benchKVDelete(b, "storage-lsm") }
func BenchmarkKVDelete_StorageMem(b *testing.B) { benchKVDelete(b, "storage-mem") }

func benchKVScan(b *testing.B, storageName string) {
	svc, cleanup := bootKV(b, storageName)
	defer cleanup()
	ctx := context.Background()
	const n = 5000
	val := make([]byte, 128)
	for i := 0; i < n; i++ {
		if err := svc.Put(ctx, fmt.Sprintf("scan/key-%05d", i), val); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cursor := ""
		for {
			items, next, err := svc.Scan(ctx, "scan/", 256, cursor)
			if err != nil {
				b.Fatal(err)
			}
			if len(items) == 0 || next == "" {
				break
			}
			cursor = next
		}
	}
}

func BenchmarkKVScan_StorageLSM(b *testing.B) { benchKVScan(b, "storage-lsm") }
func BenchmarkKVScan_StorageMem(b *testing.B) { benchKVScan(b, "storage-mem") }
