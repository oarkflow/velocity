package raft

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// Plugin wraps a Raft node as an api.Plugin, wiring its persistent state
// to a looked-up api.StorageBackend and registering it under service name
// "raft". Disabled by default in example manifests given its complexity
// and newness — see docs/ARCHITECTURE.md.
type Plugin struct {
	storageDep string

	nodeID   string
	bindAddr string
	peers    []peerInfo
	fsm      api.RaftFSM

	electionTimeoutMin time.Duration
	electionTimeoutMax time.Duration
	heartbeatInterval  time.Duration

	logger api.Logger
	raft   *Raft
}

// NewPlugin constructs the raft plugin. storageDep names the plugin whose
// Dependencies()-graph position this plugin boots after (default
// "storage-lsm"); the actual StorageBackend lookup always uses the fixed
// service name "storage" — see docs/ARCHITECTURE.md on why those are
// different namespaces.
func NewPlugin(storageDep string) *Plugin {
	if storageDep == "" {
		storageDep = "storage-lsm"
	}
	return &Plugin{storageDep: storageDep}
}

// SetFSM registers the application's state machine, applied with every
// committed log entry in order. Must be called before Start (i.e. before
// Kernel.Boot finishes Init'ing this plugin, or immediately after —
// concretely, before the kernel calls Start). If never called, a no-op
// FSM is used, which still exercises the full election/replication/commit
// path — useful for testing consensus itself independent of any
// particular application.
func (p *Plugin) SetFSM(fsm api.RaftFSM) { p.fsm = fsm }

// Raft returns the underlying node once Started, for callers that need
// direct access beyond api.RaftService (e.g. tests). Nil before Start.
func (p *Plugin) Raft() *Raft { return p.raft }

func (p *Plugin) Name() string           { return "raft" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return []string{p.storageDep} }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.logger = k.Logger()
	cfg := k.Config().Scoped("raft")

	p.nodeID = cfg.String("node_id", "")
	if p.nodeID == "" {
		return fmt.Errorf("raft: node_id must be configured")
	}
	p.bindAddr = cfg.String("bind_addr", "")
	if p.bindAddr == "" {
		return fmt.Errorf("raft: bind_addr must be configured")
	}

	peers, err := parsePeers(cfg.Raw()["peers"])
	if err != nil {
		return fmt.Errorf("raft: parsing peers: %w", err)
	}
	p.peers = peers

	p.electionTimeoutMin = cfg.Duration("election_timeout_min", 150*time.Millisecond)
	p.electionTimeoutMax = cfg.Duration("election_timeout_max", 300*time.Millisecond)
	p.heartbeatInterval = cfg.Duration("heartbeat_interval", 50*time.Millisecond)

	svc := k.Registry().MustLookup("storage")
	sb, ok := svc.(api.StorageBackend)
	if !ok {
		return fmt.Errorf("raft: service %q does not implement api.StorageBackend", "storage")
	}

	r, err := NewRaft(Config{
		ID:                 p.nodeID,
		BindAddr:           p.bindAddr,
		Peers:              p.peers,
		Storage:            sb,
		FSM:                p.fsm,
		Logger:             p.logger,
		ElectionTimeoutMin: p.electionTimeoutMin,
		ElectionTimeoutMax: p.electionTimeoutMax,
		HeartbeatInterval:  p.heartbeatInterval,
	})
	if err != nil {
		return fmt.Errorf("raft: starting node: %w", err)
	}
	p.raft = r

	return k.Registry().Provide("raft", api.RaftService(r))
}

func (p *Plugin) Start(ctx context.Context) error { return nil }

func (p *Plugin) Stop(ctx context.Context) error {
	if p.raft != nil {
		p.raft.Stop()
	}
	return nil
}

func (p *Plugin) Health() api.Health {
	if p.raft == nil {
		return api.Health{Status: "down", Detail: "not started"}
	}
	detail := "follower"
	if p.raft.IsLeader() {
		detail = "leader"
	} else if leader, ok := p.raft.Leader(); ok {
		detail = "follower, leader=" + leader
	} else {
		detail = "follower, no known leader"
	}
	return api.Health{Status: "ok", Detail: detail}
}

var _ api.Plugin = (*Plugin)(nil)

// parsePeers accepts either a []any of "id@host:port" strings (the shape
// encoding/json decodes a JSON array into, matching every other plugin's
// config convention in this codebase) or a single comma-separated string,
// for manual/CLI-friendly manifest authoring.
func parsePeers(raw any) ([]peerInfo, error) {
	var items []string
	switch v := raw.(type) {
	case nil:
		return nil, nil
	case []any:
		for _, x := range v {
			s, ok := x.(string)
			if !ok {
				return nil, fmt.Errorf("peers entries must be strings, got %T", x)
			}
			items = append(items, s)
		}
	case string:
		if strings.TrimSpace(v) == "" {
			return nil, nil
		}
		items = strings.Split(v, ",")
	default:
		return nil, fmt.Errorf("peers must be a JSON array of strings or a comma-separated string, got %T", raw)
	}

	peers := make([]peerInfo, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		idAddr := strings.SplitN(item, "@", 2)
		if len(idAddr) != 2 || idAddr[0] == "" || idAddr[1] == "" {
			return nil, fmt.Errorf("peer entry %q must be in \"id@host:port\" form", item)
		}
		peers = append(peers, peerInfo{id: idAddr[0], addr: idAddr[1]})
	}
	return peers, nil
}
