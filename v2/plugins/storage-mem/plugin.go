package mem

import (
	"context"

	"github.com/oarkflow/velocity/v2/api"
)

// Plugin registers an in-memory Engine as the kernel's "storage" service.
// Has no dependencies and no background work.
type Plugin struct {
	engine *Engine
}

// New constructs the plugin.
func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) Name() string           { return "storage-mem" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return nil }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	p.engine = NewEngine()
	return k.Registry().Provide("storage", p.engine)
}

func (p *Plugin) Start(ctx context.Context) error { return nil }
func (p *Plugin) Stop(ctx context.Context) error  { return p.engine.Close() }

func (p *Plugin) Health() api.Health {
	return api.Health{Status: "ok", Detail: "in-memory backend, no durability"}
}

var _ api.Plugin = (*Plugin)(nil)
