// Package kernel implements the Velocity v2 microkernel: plugin lifecycle
// (dependency-ordered boot/shutdown/reload), service discovery (Registry),
// a cross-cutting event bus, scoped config, and logging. It has zero
// knowledge of KV, objects, secrets, or any other concrete subsystem —
// that knowledge lives entirely in v2/plugins/*, built against the
// interfaces in v2/api.
package kernel

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"sync"

	"github.com/oarkflow/velocity/v2/api"
)

// Kernel is the default api.Kernel implementation plus the boot/shutdown/
// reload lifecycle driver. cmd/velocityd constructs one Kernel per
// process, calls Boot with every compiled-in plugin and the manifest's
// enabled set, optionally calls Reload over the process's lifetime as the
// manifest changes, and calls Shutdown on exit.
type Kernel struct {
	reg *registry
	bus *eventBus
	cfg *config
	log *stdLogger

	manifest Manifest     // the manifest currently in effect
	plugins  []api.Plugin // currently running, in dependency order

	provMu     sync.Mutex
	providedBy map[string][]string // plugin Name() -> service names it Provide()'d
}

// New constructs a Kernel scoped to the given manifest. Config lookups for
// any plugin are already available immediately after New — Boot has not
// been called yet, so plugins are not yet Init'd.
func New(m Manifest) *Kernel {
	log := newLogger()
	return &Kernel{
		reg:        newRegistry(),
		bus:        newEventBus(log),
		cfg:        newConfig(m),
		log:        log,
		manifest:   m,
		providedBy: make(map[string][]string),
	}
}

func (k *Kernel) Registry() api.Registry     { return k.reg }
func (k *Kernel) Events() api.EventBus       { return k.bus }
func (k *Kernel) Config() api.ConfigProvider { return k.cfg }
func (k *Kernel) Logger() api.Logger         { return k.log }

var _ api.Kernel = (*Kernel)(nil)

// pluginFacade is the api.Kernel a specific plugin's Init actually
// receives: identical to Kernel except Registry() returns a
// per-plugin-scoped wrapper that records what that plugin provides (see
// scopedRegistry), so Reload can later clean up exactly those entries.
type pluginFacade struct {
	*Kernel
	reg api.Registry
}

func (f *pluginFacade) Registry() api.Registry { return f.reg }

var _ api.Kernel = (*pluginFacade)(nil)

func (k *Kernel) facadeFor(pluginName string) api.Kernel {
	return &pluginFacade{
		Kernel: k,
		reg: &scopedRegistry{
			registry:   k.reg,
			pluginName: pluginName,
			onProvide:  k.recordProvide,
		},
	}
}

func (k *Kernel) recordProvide(pluginName, serviceName string) {
	k.provMu.Lock()
	defer k.provMu.Unlock()
	k.providedBy[pluginName] = append(k.providedBy[pluginName], serviceName)
}

// takeProvided removes and returns the recorded service names for
// pluginName (called when that plugin is being stopped, so its registry
// entries can be released via registry.removeAll).
func (k *Kernel) takeProvided(pluginName string) []string {
	k.provMu.Lock()
	defer k.provMu.Unlock()
	names := k.providedBy[pluginName]
	delete(k.providedBy, pluginName)
	return names
}

// Boot resolves `all` against `enabled` via resolveOrder (topological
// sort by Dependencies()/OptionalDependencies()), then calls Init on
// every resulting plugin in order followed by Start on every plugin in
// that same order. A dependency cycle, an enabled plugin with a
// dependency that isn't also enabled, or an Init/Start error aborts the
// boot and returns an error — Boot does not partially start a kernel and
// leave it running in an inconsistent state.
func (k *Kernel) Boot(ctx context.Context, all []api.Plugin, enabled map[string]bool) error {
	ordered, err := resolveOrder(all, enabled)
	if err != nil {
		return err
	}

	for _, p := range ordered {
		if err := p.Init(ctx, k.facadeFor(p.Name())); err != nil {
			return fmt.Errorf("kernel: init %q: %w", p.Name(), err)
		}
	}
	for _, p := range ordered {
		if err := p.Start(ctx); err != nil {
			return fmt.Errorf("kernel: start %q: %w", p.Name(), err)
		}
	}

	k.plugins = ordered
	k.log.Info("kernel booted", "plugins", len(ordered))
	return nil
}

// Shutdown stops every booted plugin in reverse dependency order, and
// returns the first error encountered (continuing to stop the rest so one
// misbehaving plugin doesn't leave others running).
func (k *Kernel) Shutdown(ctx context.Context) error {
	var firstErr error
	for _, p := range slices.Backward(k.plugins) {
		if err := p.Stop(ctx); err != nil {
			k.log.Error("plugin stop failed", "plugin", p.Name(), "err", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("kernel: stop %q: %w", p.Name(), err)
			}
		}
	}
	return firstErr
}

// Health reports every booted plugin's current Health(), keyed by name.
func (k *Kernel) Health() map[string]api.Health {
	h := make(map[string]api.Health, len(k.plugins))
	for _, p := range k.plugins {
		h[p.Name()] = p.Health()
	}
	return h
}

// Manifest returns the manifest currently in effect (the one from New or
// the most recent successful Reload).
func (k *Kernel) Manifest() Manifest { return k.manifest }

// Reload safely applies newManifest to a running Kernel without a full
// process restart. It is intentionally conservative:
//
//  1. newManifest is validated (parsed already by the caller, then
//     ordered via the same resolveOrder Boot uses) BEFORE anything
//     running is touched. An invalid manifest (cycle, enabled plugin
//     missing a dependency) is refused and the kernel keeps running the
//     OLD configuration completely untouched — Reload never partially
//     applies a broken manifest.
//  2. Plugins removed from the enabled set are Stopped (reverse
//     dependency order) and their registry entries released.
//  3. Plugins newly added to the enabled set are Init+Start (dependency
//     order).
//  4. A plugin whose config changed but who is still enabled is cycled
//     (Stop, then Init+Start with the new config) ONLY if nothing
//     currently running depends on it; if something does, EVERY
//     transitive dependent still enabled in the new manifest is cycled
//     too, so no plugin is left holding a stale service reference from a
//     Provider that got torn down and rebuilt. This can mean a config
//     change to a foundational plugin (e.g. the storage backend) cycles
//     most of the running system — that is the safe, correct behavior;
//     silently leaving dependents with a stale handle would be worse.
//     Plugins that are unaffected (unchanged config, no relation to any
//     changed/removed plugin) are left running untouched throughout.
//
// `all` must be the full compiled-in plugin list (e.g.
// internal/bootstrap.AllPlugins(newManifest)) — the same list Boot
// expects.
func (k *Kernel) Reload(ctx context.Context, newManifest Manifest, all []api.Plugin) error {
	newEnabled := newManifest.Enabled()

	newOrdered, err := resolveOrder(all, newEnabled)
	if err != nil {
		return fmt.Errorf("kernel: reload refused, new manifest is invalid (old configuration still running): %w", err)
	}

	oldEnabled := k.manifest.Enabled()
	oldSpec := specByName(k.manifest)
	newSpec := specByName(newManifest)

	var added, removed, configChanged []string
	for name := range newEnabled {
		if !oldEnabled[name] {
			added = append(added, name)
			continue
		}
		if !reflect.DeepEqual(oldSpec[name].Config, newSpec[name].Config) {
			configChanged = append(configChanged, name)
		}
	}
	for name := range oldEnabled {
		if !newEnabled[name] {
			removed = append(removed, name)
		}
	}

	if len(added) == 0 && len(removed) == 0 && len(configChanged) == 0 {
		k.log.Info("kernel: reload — no changes detected")
		k.manifest = newManifest // config maps may be equal-by-value but re-store for consistency
		return nil
	}

	// Every currently-running plugin that transitively depends on a
	// removed or config-changed plugin must also cycle (or, for a
	// removed dependency, that dependent's own presence in newEnabled
	// would already have failed resolveOrder above — so at this point
	// any still-enabled dependent of a removed plugin is a genuine
	// manifest error; catch it explicitly with a clearer message than
	// resolveOrder alone would give for a running-kernel-lifecycle case).
	seeds := append(append([]string{}, removed...), configChanged...)
	affected := reverseDependents(all, oldEnabled, seeds)
	for _, r := range removed {
		for name := range affected {
			if name == r {
				continue
			}
			if newEnabled[name] {
				return fmt.Errorf("kernel: reload refused, plugin %q is still enabled but depends on %q, which the new manifest disables (old configuration still running)", name, r)
			}
		}
	}

	toStop := make(map[string]bool)
	for name := range affected {
		if oldEnabled[name] {
			toStop[name] = true
		}
	}
	for _, name := range removed {
		toStop[name] = true
	}

	toStart := make(map[string]bool)
	for _, name := range added {
		toStart[name] = true
	}
	for name := range affected {
		if newEnabled[name] {
			toStart[name] = true
		}
	}

	// Stop, in reverse order of the OLD running sequence, restricted to
	// toStop.
	byName := make(map[string]api.Plugin, len(k.plugins))
	for _, p := range k.plugins {
		byName[p.Name()] = p
	}
	for _, p := range slices.Backward(k.plugins) {
		if !toStop[p.Name()] {
			continue
		}
		if err := p.Stop(ctx); err != nil {
			k.log.Error("kernel: reload stop failed", "plugin", p.Name(), "err", err)
		}
		k.reg.removeAll(k.takeProvided(p.Name()))
	}

	// Config must reflect the new manifest before Init'ing anything, so
	// plugins being (re)started see their new config.
	k.manifest = newManifest
	k.cfg = newConfig(newManifest)

	allByName := make(map[string]api.Plugin, len(all))
	for _, p := range all {
		allByName[p.Name()] = p
	}
	for _, p := range newOrdered {
		if !toStart[p.Name()] {
			continue
		}
		if err := p.Init(ctx, k.facadeFor(p.Name())); err != nil {
			return fmt.Errorf("kernel: reload init %q: %w", p.Name(), err)
		}
	}
	for _, p := range newOrdered {
		if !toStart[p.Name()] {
			continue
		}
		if err := p.Start(ctx); err != nil {
			return fmt.Errorf("kernel: reload start %q: %w", p.Name(), err)
		}
	}

	// Final running set: newOrdered already reflects correct dependency
	// order for every name in newEnabled.
	k.plugins = newOrdered
	k.log.Info("kernel: reload applied", "added", len(added), "removed", len(removed), "cycled", len(configChanged), "affected_total", len(toStop))
	return nil
}

func specByName(m Manifest) map[string]PluginSpec {
	out := make(map[string]PluginSpec, len(m.Plugins))
	for _, s := range m.Plugins {
		out[s.Name] = s
	}
	return out
}
