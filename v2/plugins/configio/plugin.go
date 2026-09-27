// Package configio implements the Velocity v2 "configio" plugin:
// api.ConfigIOService, a config-management convenience layered on top of
// whatever api.KVService is registered under the service name "kv". It
// adds no storage of its own — every Export reads through the looked-up
// KVService's Scan, every Import writes through its Put.
package configio

import (
	"context"

	"github.com/oarkflow/velocity/v2/api"
)

// ServiceName is the fixed Registry name this plugin provides its
// api.ConfigIOService under.
const ServiceName = "configio"

// scanPageSize bounds each internal Scan page while walking a prefix for
// Export — small enough that a namespace with more entries than this
// genuinely exercises pagination (see the plugin's own tests), large
// enough not to make a real export slow via excessive round trips.
const scanPageSize = 50

// Plugin implements api.Plugin and api.ConfigIOService.
type Plugin struct {
	kvDep string
	kv    api.KVService
}

// NewPlugin constructs the configio plugin. kvDep names the KV plugin this
// one depends on for boot ordering (NOT the service-lookup name, which is
// always the fixed "kv"); it defaults to "kv" when empty.
func NewPlugin(kvDep string) *Plugin {
	if kvDep == "" {
		kvDep = "kv"
	}
	return &Plugin{kvDep: kvDep}
}

func (p *Plugin) Name() string           { return "configio" }
func (p *Plugin) Version() string        { return "0.1.0" }
func (p *Plugin) Dependencies() []string { return []string{p.kvDep} }

func (p *Plugin) Init(ctx context.Context, k api.Kernel) error {
	svc := k.Registry().MustLookup("kv")
	kvSvc, ok := svc.(api.KVService)
	if !ok {
		return errNotKVService
	}
	p.kv = kvSvc
	return k.Registry().Provide(ServiceName, api.ConfigIOService(p))
}

func (p *Plugin) Start(ctx context.Context) error { return nil }
func (p *Plugin) Stop(ctx context.Context) error  { return nil }

func (p *Plugin) Health() api.Health { return api.Health{Status: "ok"} }

// scanAll walks every key under prefix across as many Scan pages as
// needed (KVService.Scan's cursor semantics: cursor names the NEXT key to
// return, not the last one returned — see api/kv.go), returning the full
// key/value set. Used by both ExportEnv and ExportJSON so pagination
// correctness only needs to live, and be tested, in one place.
func (p *Plugin) scanAll(ctx context.Context, prefix string) (map[string][]byte, error) {
	all := make(map[string][]byte)
	cursor := ""
	for {
		items, next, err := p.kv.Scan(ctx, prefix, scanPageSize, cursor)
		if err != nil {
			return nil, err
		}
		for k, v := range items {
			all[k] = v
		}
		if next == "" {
			break
		}
		cursor = next
	}
	return all, nil
}

var (
	_ api.Plugin          = (*Plugin)(nil)
	_ api.ConfigIOService = (*Plugin)(nil)
)
