package kernel

import (
	"fmt"
	"sync"

	"github.com/oarkflow/velocity/v2/api"
)

// registry is the default api.Registry implementation: a simple
// name -> service map guarded by a RWMutex. Services are provided once;
// re-providing the same name is an error rather than a silent overwrite,
// since two plugins racing to provide the same service name is always a
// manifest/wiring mistake worth surfacing loudly.
type registry struct {
	mu       sync.RWMutex
	services map[string]any
}

func newRegistry() *registry {
	return &registry{services: make(map[string]any)}
}

func (r *registry) Provide(name string, svc any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.services[name]; exists {
		return fmt.Errorf("kernel: service %q already provided", name)
	}
	r.services[name] = svc
	return nil
}

func (r *registry) Lookup(name string) (any, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.services[name]
	return s, ok
}

func (r *registry) MustLookup(name string) any {
	s, ok := r.Lookup(name)
	if !ok {
		panic(fmt.Sprintf("kernel: required service %q not registered — check plugin Dependencies() and manifest ordering", name))
	}
	return s
}

// removeAll drops the given service names, used by Kernel.Reload when a
// plugin is stopped (removed from the manifest, or being cycled to pick
// up new config) so its old service registration doesn't collide with
// a fresh Provide call when/if it (or a replacement) re-registers.
func (r *registry) removeAll(names []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range names {
		delete(r.services, n)
	}
}

var _ api.Registry = (*registry)(nil)

// scopedRegistry wraps the shared registry for one specific plugin's
// Init call, recording which service name(s) that plugin provides (via
// onProvide) so Kernel.Reload can later remove exactly those names when
// the plugin is stopped — without this, the kernel would have no way to
// know which registry entries "belong" to which plugin.
type scopedRegistry struct {
	*registry
	pluginName string
	onProvide  func(pluginName, serviceName string)
}

func (s *scopedRegistry) Provide(name string, svc any) error {
	if err := s.registry.Provide(name, svc); err != nil {
		return err
	}
	if s.onProvide != nil {
		s.onProvide(s.pluginName, name)
	}
	return nil
}

var _ api.Registry = (*scopedRegistry)(nil)
