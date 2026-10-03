package resp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// Plugin is a RESP2 server exposing KVService (always) and, when
// registered, ListService/SetService/HashService/SortedSetService/
// PubSubService, over the real Redis wire protocol. Any unmodified RESP
// client (redis-cli, go-redis, ...) can connect to it.
//
// Service lookups beyond "kv" are optional — a manifest that enables
// "resp" without "redisdata" still serves GET/SET/DEL/EXPIRE/TTL/INCR/
// DECR/KEYS/PING correctly; list/set/hash/zset/pubsub commands return a
// clear RESP error instead of panicking or hanging when unconfigured.
type Plugin struct {
	kvDep string

	kv     api.KVService
	list   api.ListService
	set    api.SetService
	hash   api.HashService
	zset   api.SortedSetService
	pubsub api.PubSubService

	addr   string
	logger api.Logger

	// tlsCertFile/tlsKeyFile enable TLS when both are set (stdlib
	// crypto/tls only, cross-platform). Both empty (the default) means
	// plain TCP, unchanged from before TLS support existed.
	tlsCertFile string
	tlsKeyFile  string

	// rateOpsPerSec/rateBurst == 0 (the default) disables per-connection
	// command rate limiting entirely. maxConnections == 0 (the default)
	// disables the connection cap. All purely additive.
	rateOpsPerSec  int
	rateBurst      int
	maxConnections int

	mu       sync.Mutex
	listener net.Listener
	accepted map[net.Conn]struct{}
	closing  bool
	wg       sync.WaitGroup
}

// NewPlugin constructs the RESP server plugin. kvDep names the plugin
// whose Dependencies()-graph position this plugin boots after (default
// "kv"); the actual KVService lookup always uses the fixed service name
// "kv" at runtime — see docs/ARCHITECTURE.md on why those are different
// namespaces.
func NewPlugin(kvDep string) *Plugin {
	if kvDep == "" {
		kvDep = "kv"
	}
	return &Plugin{kvDep: kvDep, accepted: make(map[net.Conn]struct{})}
}

func (p *Plugin) Name() string           { return "resp" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return []string{p.kvDep} }

// OptionalDependencies lists every known data-structure/pub-sub plugin
// Name() (not the "list"/"set"/... SERVICE names used for Registry.Lookup
// below — see docs/ARCHITECTURE.md on why those are two different
// namespaces). The kernel Inits any of these first if enabled, so this
// plugin's optional Registry.Lookup calls in Init are never a boot-order
// race, matching the pattern already established by plugins/web.
func (p *Plugin) OptionalDependencies() []string {
	return []string{"redisdata"}
}

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.logger = k.Logger()

	svc, ok := k.Registry().Lookup(p.kvDep)
	if !ok {
		return fmt.Errorf("resp: required service %q (kv) not registered", p.kvDep)
	}
	kv, ok := svc.(api.KVService)
	if !ok {
		return fmt.Errorf("resp: service %q does not implement api.KVService", p.kvDep)
	}
	p.kv = kv

	if svc, ok := k.Registry().Lookup("list"); ok {
		if l, ok := svc.(api.ListService); ok {
			p.list = l
		}
	}
	if svc, ok := k.Registry().Lookup("set"); ok {
		if s, ok := svc.(api.SetService); ok {
			p.set = s
		}
	}
	if svc, ok := k.Registry().Lookup("hash"); ok {
		if h, ok := svc.(api.HashService); ok {
			p.hash = h
		}
	}
	if svc, ok := k.Registry().Lookup("zset"); ok {
		if z, ok := svc.(api.SortedSetService); ok {
			p.zset = z
		}
	}
	if svc, ok := k.Registry().Lookup("pubsub"); ok {
		if ps, ok := svc.(api.PubSubService); ok {
			p.pubsub = ps
		}
	}

	p.addr = k.Config().Scoped("resp").String("addr", ":6380")

	p.tlsCertFile = k.Config().Scoped("resp").String("tls_cert_file", "")
	p.tlsKeyFile = k.Config().Scoped("resp").String("tls_key_file", "")
	if (p.tlsCertFile == "") != (p.tlsKeyFile == "") {
		return fmt.Errorf("resp: both tls_cert_file and tls_key_file must be set together (or both left empty for plain TCP), got cert=%q key=%q", p.tlsCertFile, p.tlsKeyFile)
	}

	p.rateOpsPerSec = k.Config().Scoped("resp").Int("rate_limit_ops_per_sec", 0)
	p.rateBurst = k.Config().Scoped("resp").Int("rate_limit_burst", 0)
	p.maxConnections = k.Config().Scoped("resp").Int("max_connections", 0)
	return nil
}

func (p *Plugin) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", p.addr)
	if err != nil {
		return fmt.Errorf("resp: listen: %w", err)
	}
	if p.tlsCertFile != "" {
		cert, err := tls.LoadX509KeyPair(p.tlsCertFile, p.tlsKeyFile)
		if err != nil {
			ln.Close()
			return fmt.Errorf("resp: loading TLS cert/key: %w", err)
		}
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	}
	p.mu.Lock()
	p.listener = ln
	p.mu.Unlock()

	p.wg.Add(1)
	go p.acceptLoop()
	return nil
}

// Addr returns the real listening address (useful when addr was ":0" for
// an OS-assigned port, e.g. in tests). Not part of api.Plugin — callers
// that need it type-assert to *Plugin.
func (p *Plugin) Addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}

func (p *Plugin) acceptLoop() {
	defer p.wg.Done()
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return // listener closed by Stop
		}
		p.mu.Lock()
		if p.closing {
			p.mu.Unlock()
			conn.Close()
			return
		}
		if p.maxConnections > 0 && len(p.accepted) >= p.maxConnections {
			// Refuse cleanly: close immediately rather than accepting and
			// hanging, and don't add it to `accepted` (it was never really
			// "ours" to track or force-close on Stop).
			p.mu.Unlock()
			conn.Close()
			continue
		}
		p.accepted[conn] = struct{}{}
		p.mu.Unlock()

		p.wg.Add(1)
		go p.handleConn(conn)
	}
}

func (p *Plugin) handleConn(conn net.Conn) {
	defer p.wg.Done()
	defer func() {
		p.mu.Lock()
		delete(p.accepted, conn)
		p.mu.Unlock()
		conn.Close()
	}()

	r := NewReader(conn)
	w := NewWriter(conn)
	ctx := context.Background()
	cs := &connState{}

	var limiter *tokenBucket
	if p.rateOpsPerSec > 0 {
		burst := p.rateBurst
		if burst <= 0 {
			burst = p.rateOpsPerSec
		}
		limiter = newTokenBucket(float64(p.rateOpsPerSec), float64(burst))
	}

	for {
		args, err := r.ReadCommand()
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		// Rate limiting applies to every command, including SUBSCRIBE
		// itself (the one command below that would otherwise hand off the
		// loop) — an exhausted bucket rejects it with a normal RESP error
		// and keeps the connection in normal command mode, rather than
		// silently entering subscriber mode anyway.
		if limiter != nil && !limiter.Allow() {
			w.WriteError("ERR rate limit exceeded")
			if err := w.Flush(); err != nil {
				return
			}
			continue
		}
		if isSubscribeCommand(args[0]) {
			// cmdSubscribe owns the connection's read/write loop for the
			// rest of its lifetime (real Redis subscriber-mode semantics)
			// — it never returns control back here. Real Redis also
			// disallows SUBSCRIBE inside a MULTI block; this
			// implementation doesn't special-case that combination,
			// documented in transaction.go as a narrow, intentional scope
			// gap.
			p.cmdSubscribe(ctx, r, w, args)
			return
		}
		// handleTop owns HELLO (RESP3 negotiation) and MULTI/EXEC/DISCARD
		// (transaction queuing) directly, falling through to the normal
		// per-command dispatch otherwise — see transaction.go.
		p.handleTop(ctx, w, args, cs)
		// Flush unless the client's next command is already fully in the
		// read buffer. A pipelined burst (the redis-benchmark throughput
		// case) lands in the reader's buffer as one or two socket reads;
		// flushing per command there means one write syscall per command,
		// which measured as ~2x lower pipelined throughput than real
		// Redis. A lone request/response command finds the buffer empty
		// (or holding only a partial frame) and flushes immediately, so
		// single-command latency is unchanged — see HasCompleteCommand
		// for why "fully" matters here.
		if !r.HasCompleteCommand() {
			if err := w.Flush(); err != nil {
				return
			}
		}
	}
}

// Stop closes the listener and force-closes every currently-accepted
// connection (mirroring plugins/replication/transport.go's
// connection-tracking pattern) so shutdown doesn't wait on a blocked
// client, then waits for all handler goroutines to actually exit.
func (p *Plugin) Stop(ctx context.Context) error {
	p.mu.Lock()
	p.closing = true
	if p.listener != nil {
		p.listener.Close()
	}
	for c := range p.accepted {
		c.Close()
	}
	p.mu.Unlock()

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
	}
	return nil
}

func (p *Plugin) Health() api.Health {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener == nil {
		return api.Health{Status: "down", Detail: "not started"}
	}
	return api.Health{Status: "ok", Detail: "listening on " + p.listener.Addr().String()}
}

var (
	_ api.Plugin                         = (*Plugin)(nil)
	_ api.PluginWithOptionalDependencies = (*Plugin)(nil)
)
