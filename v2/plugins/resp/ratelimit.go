package resp

import (
	"sync"
	"time"
)

// tokenBucket is a minimal, stdlib-only rate limiter: capacity `burst`
// tokens refill continuously at `rate` tokens/sec; Allow consumes one
// token if available. One instance is used per connection (not keyed
// per-client-IP like plugins/web's limiter) since each RESP connection is
// already its own isolated stream of commands.
type tokenBucket struct {
	mu       sync.Mutex
	rate     float64
	burst    float64
	tokens   float64
	lastTime time.Time
}

func newTokenBucket(rate, burst float64) *tokenBucket {
	return &tokenBucket{rate: rate, burst: burst, tokens: burst, lastTime: time.Now()}
}

func (b *tokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.lastTime).Seconds() * b.rate
	b.lastTime = now
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}
