// Package rediscomparison benchmarks Velocity v2 head-to-head against a
// REAL running redis-server, using the REAL go-redis client library
// against both — for the "velocity-resp" case, the exact same client
// talks to Velocity's plugins/resp server instead of real Redis, so it is
// a genuine same-protocol, same-client comparison, not a simulation.
package rediscomparison

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	"github.com/oarkflow/velocity/v2/plugins/redisdata"
	"github.com/oarkflow/velocity/v2/plugins/resp"
	storagemem "github.com/oarkflow/velocity/v2/plugins/storage-mem"
)

// startRealRedis launches a real redis-server subprocess bound to addr
// (e.g. "127.0.0.1:16379" — a high port, never the real Redis default, so
// this never collides with a system Redis instance), waits for it to
// accept connections, and returns a stop function.
func startRealRedis(addr string) (stop func(), err error) {
	if _, lookErr := exec.LookPath("redis-server"); lookErr != nil {
		return nil, fmt.Errorf("redis-server not found on PATH: %w", lookErr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("redis-server", "--port", port, "--bind", host, "--save", "", "--appendonly", "no")
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting redis-server: %w", err)
	}
	if err := waitForTCP(addr, 5*time.Second); err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("redis-server did not become ready: %w", err)
	}
	return func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}, nil
}

// velocityHarness boots a real Velocity kernel with storage-mem (an
// in-memory backend, matching real Redis's own in-memory nature — this is
// the fairest backend choice for this specific comparison, not
// storage-lsm's WAL-durable-to-disk design) + kv + redisdata + resp,
// exposing both a RESP endpoint (for the go-redis-over-TCP comparison)
// and direct native service handles (for the embedded, no-network-hop
// comparison).
type velocityHarness struct {
	k        *kernel.Kernel
	kvSvc    api.KVService
	listSvc  api.ListService
	setSvc   api.SetService
	respAddr string
}

func startVelocityHarness(respAddr string) (*velocityHarness, error) {
	manifest := kernel.Manifest{Plugins: []kernel.PluginSpec{
		{Name: "storage-mem", Enabled: true},
		{Name: "kv", Enabled: true},
		{Name: "redisdata", Enabled: true},
		{Name: "resp", Enabled: true, Config: map[string]any{"addr": respAddr}},
	}}
	k := kernel.New(manifest)
	all := []api.Plugin{
		storagemem.New(),
		kv.New("storage-mem"),
		redisdata.NewPlugin("storage-mem"),
		resp.NewPlugin("kv"),
	}
	ctx := context.Background()
	if err := k.Boot(ctx, all, manifest.Enabled()); err != nil {
		return nil, fmt.Errorf("velocity: boot: %w", err)
	}

	kvAny, ok := k.Registry().Lookup("kv")
	if !ok {
		return nil, fmt.Errorf("velocity: kv service not registered")
	}
	kvSvc, ok := kvAny.(api.KVService)
	if !ok {
		return nil, fmt.Errorf("velocity: kv service does not implement api.KVService")
	}

	listAny, _ := k.Registry().Lookup("list")
	listSvc, _ := listAny.(api.ListService)
	setAny, _ := k.Registry().Lookup("set")
	setSvc, _ := setAny.(api.SetService)

	if err := waitForTCP(respAddr, 3*time.Second); err != nil {
		return nil, fmt.Errorf("velocity resp server did not become ready: %w", err)
	}

	return &velocityHarness{k: k, kvSvc: kvSvc, listSvc: listSvc, setSvc: setSvc, respAddr: respAddr}, nil
}

func (h *velocityHarness) Close() error {
	return h.k.Shutdown(context.Background())
}

func waitForTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", addr)
}

// newGoredisClient is a small helper so every benchmark constructs its
// go-redis client identically regardless of which server it points at.
func newGoredisClient(addr string) *goredis.Client {
	return goredis.NewClient(&goredis.Options{Addr: addr, PoolSize: 16})
}
