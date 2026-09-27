// Package kernel implements the Velocity v2 microkernel: plugin lifecycle
// (dependency-ordered boot/shutdown), service discovery (Registry), a
// cross-cutting event bus, scoped config, and logging. It has zero
// knowledge of KV, objects, secrets, or any other concrete subsystem —
// that knowledge lives entirely in v2/plugins/*, built against the
// interfaces in v2/api.
package kernel

import (
	"context"
	"fmt"
	"slices"

	"github.com/oarkflow/velocity/v2/api"
)

// Kernel is the default api.Kernel implementation plus the boot/shutdown
// lifecycle driver. cmd/velocityd constructs one Kernel per process,
// calls Boot with every compiled-in plugin and the manifest's enabled
// set, and Shutdown on exit.
type Kernel struct {
	reg *registry
	bus *eventBus
	cfg *config
	log *stdLogger

	plugins []api.Plugin // filled by Boot, in dependency order
}

// New constructs a Kernel scoped to the given manifest. Config lookups for
// any plugin are already available immediately after New — Boot has not
// been called yet, so plugins are not yet Init'd.
func New(m Manifest) *Kernel {
	log := newLogger()
	return &Kernel{
		reg: newRegistry(),
		bus: newEventBus(log),
		cfg: newConfig(m),
		log: log,
	}
}

func (k *Kernel) Registry() api.Registry     { return k.reg }
func (k *Kernel) Events() api.EventBus       { return k.bus }
func (k *Kernel) Config() api.ConfigProvider { return k.cfg }
func (k *Kernel) Logger() api.Logger         { return k.log }

var _ api.Kernel = (*Kernel)(nil)

// Boot topologically sorts `all` by each plugin's Dependencies(),
// restricted to the names in `enabled`, then calls Init on every plugin in
// that order followed by Start on every plugin in that same order. A
// dependency cycle, an enabled plugin with a dependency that isn't also
// enabled, or an Init/Start error aborts the boot and returns an error —
// Boot does not partially start a kernel and leave it running in an
// inconsistent state.
func (k *Kernel) Boot(ctx context.Context, all []api.Plugin, enabled map[string]bool) error {
	byName := make(map[string]api.Plugin, len(all))
	for _, p := range all {
		byName[p.Name()] = p
	}

	state := make(map[string]int) // 0=unvisited, 1=visiting, 2=done
	var ordered []api.Plugin

	var visit func(name string, chain []string) error
	visit = func(name string, chain []string) error {
		switch state[name] {
		case 2:
			return nil
		case 1:
			return fmt.Errorf("kernel: dependency cycle detected: %v -> %s", chain, name)
		}
		if !enabled[name] {
			return nil
		}
		p, ok := byName[name]
		if !ok {
			return fmt.Errorf("kernel: plugin %q is enabled in the manifest but not registered with Boot", name)
		}
		state[name] = 1
		for _, dep := range p.Dependencies() {
			if err := visit(dep, append(chain, name)); err != nil {
				return err
			}
			if !enabled[dep] {
				return fmt.Errorf("kernel: plugin %q depends on %q, which is not enabled in the manifest", name, dep)
			}
		}
		// Optional dependencies get priority ordering (Init'd first) when
		// enabled, but are silently skipped when not — see
		// api.PluginWithOptionalDependencies.
		if opt, ok := p.(api.PluginWithOptionalDependencies); ok {
			for _, dep := range opt.OptionalDependencies() {
				if dep == "" || !enabled[dep] {
					continue
				}
				if err := visit(dep, append(chain, name)); err != nil {
					return err
				}
			}
		}
		state[name] = 2
		ordered = append(ordered, p)
		return nil
	}

	for name := range enabled {
		if err := visit(name, nil); err != nil {
			return err
		}
	}

	for _, p := range ordered {
		if err := p.Init(ctx, k); err != nil {
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
