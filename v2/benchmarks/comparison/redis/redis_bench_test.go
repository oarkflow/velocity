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
