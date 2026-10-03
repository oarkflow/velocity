package rediscomparison

import (
	"context"
	"fmt"
	"os"
	"testing"

	goredis "github.com/redis/go-redis/v9"
)

const (
	realRedisAddr = "127.0.0.1:16379"
	velocityAddr  = "127.0.0.1:16380"
)

var (
	stopRealRedis func()
	velocityH     *velocityHarness

	realClient     *goredis.Client
	velocityClient *goredis.Client
)

func TestMain(m *testing.M) {
	code := runMain(m)
	os.Exit(code)
}

func runMain(m *testing.M) int {
	stop, err := startRealRedis(realRedisAddr)
	if err != nil {
		fmt.Println("SKIP: real redis-server unavailable:", err)
		return 0
	}
	stopRealRedis = stop
	defer stopRealRedis()

	h, err := startVelocityHarness(velocityAddr)
	if err != nil {
		fmt.Println("FATAL: velocity harness failed to start:", err)
		return 1
	}
	velocityH = h
	defer h.Close() //nolint:errcheck

	realClient = newGoredisClient(realRedisAddr)
	defer realClient.Close()
	velocityClient = newGoredisClient(velocityAddr)
	defer velocityClient.Close()

	ctx := context.Background()
	if err := realClient.Ping(ctx).Err(); err != nil {
		fmt.Println("FATAL: could not PING real redis-server:", err)
		return 1
	}
	if err := velocityClient.Ping(ctx).Err(); err != nil {
		fmt.Println("FATAL: could not PING velocity resp server:", err)
		return 1
	}

	return m.Run()
}

// --- SET ---

func BenchmarkSet(b *testing.B) {
	ctx := context.Background()
	b.Run("redis", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := realClient.Set(ctx, fmt.Sprintf("k%d", i), "hello world value", 0).Err(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("velocity-resp", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := velocityClient.Set(ctx, fmt.Sprintf("k%d", i), "hello world value", 0).Err(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("velocity-native", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := velocityH.kvSvc.Put(ctx, fmt.Sprintf("nk%d", i), []byte("hello world value")); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// --- GET ---

func BenchmarkGet(b *testing.B) {
	ctx := context.Background()
	const n = 10000
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("gk%d", i)
		if err := realClient.Set(ctx, key, "hello world value", 0).Err(); err != nil {
			b.Fatal(err)
		}
		if err := velocityClient.Set(ctx, key, "hello world value", 0).Err(); err != nil {
			b.Fatal(err)
		}
		if err := velocityH.kvSvc.Put(ctx, key, []byte("hello world value")); err != nil {
			b.Fatal(err)
		}
	}

	b.Run("redis", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := realClient.Get(ctx, fmt.Sprintf("gk%d", i%n)).Err(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("velocity-resp", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := velocityClient.Get(ctx, fmt.Sprintf("gk%d", i%n)).Err(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("velocity-native", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, _, err := velocityH.kvSvc.Get(ctx, fmt.Sprintf("gk%d", i%n)); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// --- INCR ---

func BenchmarkIncr(b *testing.B) {
	ctx := context.Background()
	b.Run("redis", func(b *testing.B) {
		b.ReportAllocs()
		key := "counter-redis"
		for i := 0; i < b.N; i++ {
			if err := realClient.Incr(ctx, key).Err(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("velocity-resp", func(b *testing.B) {
		b.ReportAllocs()
		key := "counter-velocity-resp"
		for i := 0; i < b.N; i++ {
			if err := velocityClient.Incr(ctx, key).Err(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("velocity-native", func(b *testing.B) {
		b.ReportAllocs()
		key := "counter-velocity-native"
		for i := 0; i < b.N; i++ {
			if _, err := velocityH.kvSvc.Incr(ctx, key, 1); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// --- LPUSH + LRANGE ---

func BenchmarkLPushLRange(b *testing.B) {
	ctx := context.Background()

	b.Run("redis", func(b *testing.B) {
		b.ReportAllocs()
		key := "list-redis"
		for i := 0; i < b.N; i++ {
			if err := realClient.LPush(ctx, key, fmt.Sprintf("v%d", i)).Err(); err != nil {
				b.Fatal(err)
			}
		}
		if err := realClient.LRange(ctx, key, 0, 9).Err(); err != nil {
			b.Fatal(err)
		}
	})
	b.Run("velocity-resp", func(b *testing.B) {
		b.ReportAllocs()
		key := "list-velocity-resp"
		for i := 0; i < b.N; i++ {
			if err := velocityClient.LPush(ctx, key, fmt.Sprintf("v%d", i)).Err(); err != nil {
				b.Fatal(err)
			}
		}
		if err := velocityClient.LRange(ctx, key, 0, 9).Err(); err != nil {
			b.Fatal(err)
		}
	})
	b.Run("velocity-native", func(b *testing.B) {
		if velocityH.listSvc == nil {
			b.Skip("list service not registered")
		}
		b.ReportAllocs()
		key := "list-velocity-native"
		for i := 0; i < b.N; i++ {
			if _, err := velocityH.listSvc.LPush(ctx, key, []byte(fmt.Sprintf("v%d", i))); err != nil {
				b.Fatal(err)
			}
		}
		if _, err := velocityH.listSvc.LRange(ctx, key, 0, 9); err != nil {
			b.Fatal(err)
		}
	})
}

// --- SADD + SMEMBERS ---

func BenchmarkSAddSMembers(b *testing.B) {
	ctx := context.Background()

	b.Run("redis", func(b *testing.B) {
		b.ReportAllocs()
		key := "set-redis"
		for i := 0; i < b.N; i++ {
			if err := realClient.SAdd(ctx, key, fmt.Sprintf("m%d", i)).Err(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("velocity-resp", func(b *testing.B) {
		b.ReportAllocs()
		key := "set-velocity-resp"
		for i := 0; i < b.N; i++ {
			if err := velocityClient.SAdd(ctx, key, fmt.Sprintf("m%d", i)).Err(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("velocity-native", func(b *testing.B) {
		if velocityH.setSvc == nil {
			b.Skip("set service not registered")
		}
		b.ReportAllocs()
		key := "set-velocity-native"
		for i := 0; i < b.N; i++ {
			if _, err := velocityH.setSvc.SAdd(ctx, key, []byte(fmt.Sprintf("m%d", i))); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// --- pipelined throughput (redis-benchmark methodology) ---
//
// The single-command benchmarks above measure per-command LATENCY through
// one round trip each. Real Redis's peak throughput claim comes from
// pipelining — many commands in flight per round trip — which is exactly
// what redis-benchmark does and what the earlier RESULTS.md explicitly
// flagged as untested here. Each iteration of these benchmarks sends one
// pipeline of pipelineDepth commands in a single round trip; the reported
// ns/op is PER PIPELINE, so per-command cost is ns/op / pipelineDepth,
// and throughput is pipelineDepth / ns/op * 1e9 ops/sec.

const pipelineDepth = 64

func benchPipelineSet(b *testing.B, client *goredis.Client, tag string) {
	b.Run(tag, func(b *testing.B) {
		ctx := context.Background()
		b.ReportAllocs()
		for b.Loop() {
			pipe := client.Pipeline()
			for j := 0; j < pipelineDepth; j++ {
				pipe.Set(ctx, fmt.Sprintf("pipe-%s-%d", tag, j), "hello world value", 0)
			}
			if _, err := pipe.Exec(ctx); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func benchPipelineGet(b *testing.B, client *goredis.Client, tag string) {
	b.Run(tag, func(b *testing.B) {
		ctx := context.Background()
		for j := 0; j < 1000; j++ {
			if err := client.Set(ctx, fmt.Sprintf("pg-%s-%d", tag, j), "hello world value", 0).Err(); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs()
		i := 0
		for b.Loop() {
			pipe := client.Pipeline()
			for j := 0; j < pipelineDepth; j++ {
				pipe.Get(ctx, fmt.Sprintf("pg-%s-%d", tag, (i+j)%1000))
			}
			if _, err := pipe.Exec(ctx); err != nil {
				b.Fatal(err)
			}
			i += pipelineDepth
		}
	})
}

func BenchmarkPipelineSet(b *testing.B) {
	benchPipelineSet(b, realClient, "redis")
	benchPipelineSet(b, velocityClient, "velocity-resp")
}

func BenchmarkPipelineGet(b *testing.B) {
	benchPipelineGet(b, realClient, "redis")
	benchPipelineGet(b, velocityClient, "velocity-resp")
}
