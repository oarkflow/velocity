package replication

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// Plugin is the api.Plugin implementation wiring Transport, Membership,
// and the optional event-bus fanout together, and registering "cluster"
// (api.ClusterMembership) and "replication.transport"
// (api.ReplicationTransport) in the kernel registry.
type Plugin struct {
	nodeID   string
	bindAddr string
	seed     string

	heartbeatInterval time.Duration
	failAfter         time.Duration
	enableFanout      bool

	transport  *Transport
	membership *Membership
	fanout     *fanout

	log api.Logger
}

// NewPlugin constructs the replication plugin. nodeID/bindAddr/seed can be
// left empty and supplied via config instead (config takes precedence if
// both are set — see Init).
func NewPlugin(nodeID, bindAddr, seed string) *Plugin {
	return &Plugin{nodeID: nodeID, bindAddr: bindAddr, seed: seed}
}

func (p *Plugin) Name() string           { return "replication" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return nil }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	cfg := k.Config().Scoped(p.Name())
	p.log = k.Logger()

	nodeID := cfg.String("node_id", p.nodeID)
	if nodeID == "" {
		nodeID = fmt.Sprintf("node-%d", time.Now().UnixNano())
	}
	bindAddr := cfg.String("bind_addr", p.bindAddr)
	if bindAddr == "" {
		bindAddr = "127.0.0.1:0"
	}
	seed := cfg.String("seed", p.seed)
	p.heartbeatInterval = cfg.Duration("heartbeat_interval", 2*time.Second)
	p.failAfter = cfg.Duration("fail_after", 10*time.Second)
	p.enableFanout = cfg.Bool("enable_fanout", true)
	p.seed = seed
	p.nodeID = nodeID
	p.bindAddr = bindAddr

	p.transport = NewTransport(nodeID, bindAddr)

	if err := k.Registry().Provide("replication.transport", p.transport); err != nil {
		return fmt.Errorf("replication: %w", err)
	}

	// self.Address is resolved once Start binds the listener (needed for
	// ":0" to become a real port); Membership is constructed here with a
	// placeholder address and updated in Start once Transport.Addr() is
	// known.
	self := api.NodeInfo{ID: nodeID, Address: bindAddr}
	p.membership = NewMembership(self, p.transport, p.heartbeatInterval, p.failAfter)
	p.membership.SetEventBus(k.Events())

	if err := k.Registry().Provide("cluster", p.membership); err != nil {
		return fmt.Errorf("replication: %w", err)
	}

	if p.enableFanout {
		p.fanout = newFanout(p.membership, p.transport, p.log)
		p.fanout.subscribe(k.Events())
	}

	// Single Transport.OnReceive dispatcher: decode the shared envelope
	// and route to whichever of Membership/fanout understands it. See
	// envelope.go's doc comment for why this indirection exists.
	p.transport.OnReceive(func(from api.NodeInfo, payload []byte) {
		var env frameEnvelope
		if err := json.Unmarshal(payload, &env); err != nil {
			return
		}
		switch env.Kind {
		case "control":
			if env.Control != nil {
				p.membership.HandleControl(from, *env.Control)
			}
		case "replica":
			if env.Replica != nil && p.fanout != nil {
				p.fanout.HandleReplica(from, *env.Replica)
			}
		}
	})

	return nil
}

func (p *Plugin) Start(ctx context.Context) error {
	if err := p.transport.Start(); err != nil {
		return fmt.Errorf("replication: %w", err)
	}
	// Now that the listener is bound, refresh self's advertised address
	// (important when bindAddr was ":0" / "host:0").
	if addr := p.transport.Addr(); addr != "" {
		p.membership.mu.Lock()
		self := p.membership.self
		self.Address = addr
		p.membership.self = self
		p.membership.members[self.ID] = self
		p.membership.mu.Unlock()
	}

	p.membership.Start()

	if p.fanout != nil {
		p.fanout.start()
	}

	if p.seed != "" {
		if err := p.membership.Join(ctx, p.seed); err != nil {
			p.log.Warn("replication: join seed failed", "seed", p.seed, "err", err)
		}
	}
	return nil
}

func (p *Plugin) Stop(ctx context.Context) error {
	if p.fanout != nil {
		p.fanout.stop()
	}
	_ = p.membership.Leave(ctx)
	p.membership.Stop()
	return p.transport.Stop()
}

func (p *Plugin) Health() api.Health {
	if p.membership == nil {
		return api.Health{Status: "down", Detail: "not initialized"}
	}
	n := len(p.membership.Members())
	return api.Health{Status: "ok", Detail: fmt.Sprintf("%d cluster member(s)", n)}
}

var _ api.Plugin = (*Plugin)(nil)
