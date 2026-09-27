// Package sql implements Velocity v2's SQL plugin: it exposes api.SQLEngine
// (Exec/Query/Begin) by parsing statements with the real, proven
// github.com/oarkflow/sqlparser parser (the same one v1's pkg/sqldriver
// used) and executing a basic CRUD+WHERE subset directly against an
// api.KVService looked up from the kernel registry.
//
// This is an explicit architectural improvement over v1: v1's pkg/sqldriver
// was a database/sql/driver implementation built directly atop the
// monolithic root DB type. Here the SQL engine depends only on the
// api.KVService interface, so it works against any KV implementation the
// manifest wires it to, not one hardwired storage engine.
//
// Table rows are stored as KV entries under:
//
//	sql/<table>/schema           JSON-encoded Schema (columns, primary key, auto-increment)
//	sql/<table>/row/<pk>         JSON-encoded row (api.Row)
//	sql/<table>/seq              auto-increment counter (via KVService.Incr)
//
// There is no secondary indexing in this first pass: non-primary-key WHERE
// clauses are evaluated with a full table scan. That is a documented
// performance limitation, not a correctness one.
package sql

import (
	"context"
	"fmt"

	"github.com/oarkflow/velocity/v2/api"
)

// Plugin wires an Engine into the kernel. Construct with NewPlugin and
// register it with cmd/velocityd's plugin list.
type Plugin struct {
	kvDep string
	eng   *Engine
}

// NewPlugin returns a sql Plugin depending on the KVService plugin named
// kvDep (defaults to "kv" for boot ordering; the service is always looked
// up under the fixed registry name "kv" regardless of which concrete
// plugin provided it).
func NewPlugin(kvDep string) *Plugin {
	if kvDep == "" {
		kvDep = "kv"
	}
	return &Plugin{kvDep: kvDep}
}

func (p *Plugin) Name() string    { return "sql" }
func (p *Plugin) Version() string { return "0.1.0" }

func (p *Plugin) Dependencies() []string { return []string{p.kvDep} }

func (p *Plugin) Init(_ context.Context, k api.Kernel) error {
	svc := k.Registry().MustLookup("kv")
	kv, ok := svc.(api.KVService)
	if !ok {
		return fmt.Errorf("sql: service %q registered under name %q is not an api.KVService (got %T)", p.kvDep, "kv", svc)
	}
	p.eng = NewEngine(kv)
	return k.Registry().Provide("sql", p.eng)
}

func (p *Plugin) Start(_ context.Context) error { return nil }
func (p *Plugin) Stop(_ context.Context) error  { return nil }

func (p *Plugin) Health() api.Health {
	if p.eng == nil {
		return api.Health{Status: "down", Detail: "not initialized"}
	}
	return api.Health{Status: "ok"}
}

var _ api.Plugin = (*Plugin)(nil)
