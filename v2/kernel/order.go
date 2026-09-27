package kernel

import (
	"fmt"

	"github.com/oarkflow/velocity/v2/api"
)

// resolveOrder topologically sorts `all` by each plugin's Dependencies()
// (and, when enabled, OptionalDependencies()), restricted to the names in
// `enabled`. It is pure — it does not call Init/Start on anything — so
// both Boot and Reload can validate/order a manifest before touching any
// running state. A dependency cycle, an enabled plugin with a dependency
// that isn't also enabled, or an enabled plugin missing from `all` is a
// clear, returned error.
func resolveOrder(all []api.Plugin, enabled map[string]bool) ([]api.Plugin, error) {
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
			return nil, err
		}
	}
	return ordered, nil
}

// reverseDependents returns the set of plugin names (restricted to
// `enabled`) that transitively depend — via Dependencies() or an enabled
// OptionalDependencies() entry — on any name in `seeds`, plus the seeds
// themselves. Used by Reload to find every currently-running plugin that
// holds a reference to a service a changed/removed plugin provides, so
// they can be safely cycled (or the reload refused) instead of left
// holding a stale service handle.
func reverseDependents(all []api.Plugin, enabled map[string]bool, seeds []string) map[string]bool {
	// dependsOn[a] = names a depends on (hard + enabled-optional)
	dependsOn := make(map[string][]string, len(all))
	for _, p := range all {
		if !enabled[p.Name()] {
			continue
		}
		deps := append([]string{}, p.Dependencies()...)
		if opt, ok := p.(api.PluginWithOptionalDependencies); ok {
			for _, d := range opt.OptionalDependencies() {
				if d != "" && enabled[d] {
					deps = append(deps, d)
				}
			}
		}
		dependsOn[p.Name()] = deps
	}

	affected := make(map[string]bool, len(seeds))
	for _, s := range seeds {
		affected[s] = true
	}

	// Fixed-point: repeatedly add any enabled plugin that depends on
	// something already in `affected`, until nothing new is added.
	for changed := true; changed; {
		changed = false
		for name, deps := range dependsOn {
			if affected[name] {
				continue
			}
			for _, d := range deps {
				if affected[d] {
					affected[name] = true
					changed = true
					break
				}
			}
		}
	}
	return affected
}
