package web

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// tokenBucket is a minimal, stdlib-only rate limiter: capacity `burst`
// tokens refill continuously at `rate` tokens/sec; Allow consumes one
// token if available. No background goroutine — refill is computed
// lazily from elapsed wall-clock time on each Allow call, so an idle
// bucket costs nothing between calls.
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

// perClientLimiter keys one tokenBucket per client IP. Buckets are never
// actively evicted (this is a simple, bounded-effort limiter, not a full
// LRU cache) — a deployment with a very large number of distinct client
// IPs over its lifetime will accumulate one small struct per IP, which is
// an acceptable, documented trade-off for the simplicity of a stdlib-only
// implementation; it is not unbounded per-request growth.
type perClientLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*tokenBucket
}

func newPerClientLimiter(rate, burst float64) *perClientLimiter {
	return &perClientLimiter{rate: rate, burst: burst, buckets: make(map[string]*tokenBucket)}
}

func (l *perClientLimiter) Allow(key string) bool {
	l.mu.Lock()
	b, ok := l.buckets[key]
	if !ok {
		b = newTokenBucket(l.rate, l.burst)
		l.buckets[key] = b
	}
	l.mu.Unlock()
	return b.Allow()
}

// clientIPFromRequest extracts the client IP for rate-limit keying,
// stripping the port from RemoteAddr; if RemoteAddr isn't a valid
// host:port (e.g. in a hand-constructed test request), the raw value is
// used as-is rather than erroring the request.
func clientIPFromRequest(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimitMiddleware rejects with 429 + Retry-After once the calling
// client IP's bucket is exhausted. Applied outermost (before auth/metrics
// wrapping) so a rate-limited request never reaches the auth check or
// gets counted in request metrics.
func (p *Plugin) rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.rateLimiter.Allow(clientIPFromRequest(r)) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}
