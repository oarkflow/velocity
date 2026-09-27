package metrics

import (
	"context"

	"github.com/oarkflow/velocity/v2/api"
)

// Plugin wires a Sink into the kernel under service name "metrics". It has
// no dependencies — every other plugin depends on it optionally, never the
// reverse.
type Plugin struct {
	sink *Sink
}

// NewPlugin constructs the metrics plugin.
func NewPlugin() *Plugin {
	return &Plugin{sink: New()}
}

func (p *Plugin) Name() string           { return "metrics" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return nil }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	return k.Registry().Provide("metrics", p.sink)
}

func (p *Plugin) Start(ctx context.Context) error { return nil }
func (p *Plugin) Stop(ctx context.Context) error  { return nil }

func (p *Plugin) Health() api.Health {
	return api.Health{Status: "ok"}
}

var _ api.Plugin = (*Plugin)(nil)
