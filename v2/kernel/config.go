package kernel

import (
	"encoding/json"
	"os"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// PluginSpec is one entry in a Manifest: which plugin, whether it's
// enabled, and its scoped config. Config values come in as JSON-decoded
// `any` (string/float64/bool/map/slice), matching encoding/json's default
// decoding — PluginConfig's typed accessors handle the float64-vs-int
// conversion so plugin authors don't have to.
type PluginSpec struct {
	Name    string         `json:"name"`
	Enabled bool           `json:"enabled"`
	Config  map[string]any `json:"config"`
}

// Manifest is the full set of plugins a velocityd instance should load.
// This is what makes the system config-driven rather than requiring a
// recompile to add/remove a subsystem: a minimal manifest might list only
// storage-mem + kv; a full one lists every plugin in v2/plugins.
type Manifest struct {
	Plugins []PluginSpec `json:"plugins"`
}

// Enabled returns the set of enabled plugin names, for use with
// Kernel.Boot.
func (m Manifest) Enabled() map[string]bool {
	out := make(map[string]bool, len(m.Plugins))
	for _, p := range m.Plugins {
		if p.Enabled {
			out[p.Name] = true
		}
	}
	return out
}

// LoadManifestJSON reads and decodes a JSON manifest file. YAML is a
// natural follow-up format (the PluginSpec/Manifest field names are
// chosen to work as either), but is intentionally left out of the initial
// rework to avoid adding a third-party dependency to the kernel — the
// stdlib JSON path keeps the kernel dependency-free.
func LoadManifestJSON(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// config is the default api.ConfigProvider implementation.
type config struct {
	scoped map[string]map[string]any
}

func newConfig(m Manifest) *config {
	c := &config{scoped: make(map[string]map[string]any, len(m.Plugins))}
	for _, p := range m.Plugins {
		c.scoped[p.Name] = p.Config
	}
	return c
}

func (c *config) Scoped(pluginName string) api.PluginConfig {
	return &pluginConfig{data: c.scoped[pluginName]}
}

type pluginConfig struct{ data map[string]any }

func (p *pluginConfig) Raw() map[string]any { return p.data }

func (p *pluginConfig) String(key, def string) string {
	if v, ok := p.data[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

func (p *pluginConfig) Int(key string, def int) int {
	if v, ok := p.data[key]; ok {
		switch n := v.(type) {
		case float64: // encoding/json decodes JSON numbers as float64
			return int(n)
		case int:
			return n
		}
	}
	return def
}

func (p *pluginConfig) Bool(key string, def bool) bool {
	if v, ok := p.data[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}

func (p *pluginConfig) Duration(key string, def time.Duration) time.Duration {
	if v, ok := p.data[key]; ok {
		switch d := v.(type) {
		case string:
			if parsed, err := time.ParseDuration(d); err == nil {
				return parsed
			}
		case float64:
			return time.Duration(d)
		}
	}
	return def
}

var _ api.ConfigProvider = (*config)(nil)
var _ api.PluginConfig = (*pluginConfig)(nil)
