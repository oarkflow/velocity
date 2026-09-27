// Package api defines the contracts shared by the Velocity v2 microkernel
// and every plugin. It contains interfaces only — no implementations live
// here. The kernel package implements Kernel/Registry/EventBus/ConfigProvider
// /Logger; each plugins/* package implements one or more of the service
// interfaces (StorageBackend, KVService, ObjectService, ...) declared
// throughout this package.
package api

import (
	"context"
	"time"
)

// Health reports a plugin's current operational status, surfaced through
// Kernel.Health() and typically exposed on a status/monitoring endpoint.
type Health struct {
	Status string // "ok", "degraded", "down"
	Detail string
}

// Plugin is the unit of extensibility in Velocity v2. Every subsystem —
// the storage engine, KV, object storage, secrets, crypto, auth,
// compliance, replication, SQL, search, the web/S3 gateway, metrics — is a
// Plugin. The kernel does nothing but resolve Plugin dependency order and
// drive this lifecycle; it has no built-in knowledge of what any plugin
// does.
type Plugin interface {
	// Name uniquely identifies the plugin, e.g. "storage-lsm", "kv", "auth-jwt".
	Name() string

	// Version is a free-form version string for the plugin build.
	Version() string

	// Dependencies lists the Names of plugins that must be Init'd (and
	// Start'd) before this one. The kernel topologically sorts the enabled
	// plugin set by this graph before booting; a cycle is a boot error.
	Dependencies() []string

	// Init wires the plugin against the kernel: look up services it depends
	// on via k.Registry().Lookup, register the services it provides via
	// k.Registry().Provide, and subscribe to cross-cutting events via
	// k.Events().Subscribe. Init must not start background work — that
	// belongs in Start. Init runs in dependency order.
	Init(ctx context.Context, k Kernel) error

	// Start begins any background work (timers, listeners, schedulers).
	// Runs in the same order as Init, after all plugins have Init'd.
	Start(ctx context.Context) error

	// Stop gracefully shuts down background work. Called in reverse
	// dependency order during kernel shutdown.
	Stop(ctx context.Context) error

	// Health reports current plugin health.
	Health() Health
}

// PluginWithOptionalDependencies is an extra interface a Plugin may
// implement alongside Plugin itself, for a dependency that should be
// Init'd first *if* it happens to be enabled, without requiring it —
// unlike Dependencies(), an optional dependency that isn't enabled is
// simply skipped rather than making Boot fail.
//
// This exists for plugins like the web gateway, which can look up an
// auth provider by service name and use it if present, but must still
// boot successfully in a manifest that enables no auth plugin at all.
// Without this, boot order between two plugins with no Dependencies()
// edge between them is unspecified (Boot iterates the enabled set,
// which is a map), so an optional lookup at Init time could race
// against the optional dependency's own Init.
type PluginWithOptionalDependencies interface {
	Plugin
	OptionalDependencies() []string
}

// Kernel is the facade every plugin receives in Init. It intentionally
// exposes only generic mechanisms (service discovery, events, config,
// logging) — it has no knowledge of KV, objects, secrets, or any other
// concrete subsystem. That knowledge lives entirely in plugins.
type Kernel interface {
	Registry() Registry
	Events() EventBus
	Config() ConfigProvider
	Logger() Logger
}

// Registry is the service directory plugins use to publish what they
// provide and discover what they depend on. Service names are plain
// strings by convention (see plugins/*/README or each plugin's doc
// comment for the name it registers under, e.g. "storage", "kv", "crypto",
// "auth", "compliance"). Callers type-assert the returned value to the
// interface they expect (e.g. api.KVService).
type Registry interface {
	// Provide registers a service under name. Returns an error if name is
	// already provided — services are not silently overwritten.
	Provide(name string, svc any) error

	// Lookup returns the service registered under name, if any.
	Lookup(name string) (any, bool)

	// MustLookup panics if name is not registered. Intended for use inside
	// Init/Start after dependency resolution guarantees the dependency's
	// Init has already run — a missing service at that point is a wiring
	// bug, not a runtime condition to handle gracefully.
	MustLookup(name string) any
}

// ConfigProvider hands out a config view scoped to a single plugin, so
// plugins never see each other's configuration.
type ConfigProvider interface {
	Scoped(pluginName string) PluginConfig
}

// PluginConfig is a single plugin's slice of the manifest's config map.
// Accessors take a default so plugins can be written against config keys
// that may be absent (e.g. running with defaults in a minimal manifest).
type PluginConfig interface {
	String(key, def string) string
	Int(key string, def int) int
	Bool(key string, def bool) bool
	Duration(key string, def time.Duration) time.Duration
	// Raw returns the underlying config map for plugins that need
	// structured values the typed accessors don't cover.
	Raw() map[string]any
}

// Logger is the structured logging facade handed to every plugin.
type Logger interface {
	Debug(msg string, kv ...any)
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
	Error(msg string, kv ...any)
}
