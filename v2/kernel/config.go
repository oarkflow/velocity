package kernel

import (
	"context"
	"encoding/json"
	"time"

	bcl "github.com/oarkflow/config/parsers/bcl"
	"github.com/oarkflow/config/providers/file"

	oarkconfig "github.com/oarkflow/config"

	"github.com/oarkflow/velocity/v2/api"
)

// PluginSpec is one entry in a Manifest: which plugin, whether it's
// enabled, and its scoped config. Config values come in as decoded `any`
// (string/json.Number/bool/map/slice — see PluginConfig's typed
// accessors, which handle the json.Number-vs-int/float conversion so
// plugin authors don't have to).
type PluginSpec struct {
	Name    string         `json:"name" bcl:",id"`
	Enabled bool           `json:"enabled" bcl:"enabled"`
	Config  map[string]any `json:"config" bcl:"config"`
}

// Manifest is the full set of plugins a velocityd instance should load.
// This is what makes the system config-driven rather than requiring a
// recompile to add/remove a subsystem: a minimal manifest might list only
// storage-mem + kv; a full one lists every plugin in v2/plugins.
//
// The `bcl:"plugins,block"` tag is only consulted by the raw
// github.com/oarkflow/bcl package (e.g. bcl.Marshal in tests, to
// (re-)generate a manifest file in genuine labeled-block syntax); the
// real manifest-loading path, LoadManifestBCL below, reads the parsed
// "$blocks" structure directly instead, since oarkconfig.Decode doesn't
// understand blocks at all (see its doc comment).
type Manifest struct {
	Plugins []PluginSpec `json:"plugins" bcl:"plugins,block"`
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

// LoadManifestBCL reads and decodes a BCL (github.com/oarkflow/bcl)
// manifest file via github.com/oarkflow/config's Manager — the same
// production config-loading library used elsewhere in this codebase,
// rather than a hand-rolled file reader — so the manifest gets that
// library's real parsing/validation/hot-reload plumbing for free. The
// file must exist (file.Required); a missing or malformed manifest is a
// startup error, not a silent empty-manifest fallback.
//
// The manifest uses genuine BCL labeled-block syntax, one repeated
// "plugins" block per plugin (the label is the plugin name):
//
//	plugins "storage-lsm" {
//	  enabled true
//	  config {
//	    dir "./data/velocityd"
//	  }
//	}
//
// github.com/oarkflow/config's generic Decode[T] doesn't understand
// labeled/repeated BCL blocks (it round-trips the parsed tree through
// encoding/json, which has no notion of a block's label) — the parser
// instead surfaces every block under a "$blocks" tree entry, each as
// {"type": <block keyword>, "id": <label>, "body": <block contents>}.
// So this reads that raw structure directly rather than going through
// oarkconfig.Decode.
func LoadManifestBCL(path string) (Manifest, error) {
	mgr, err := oarkconfig.Load(context.Background(),
		oarkconfig.WithProviders(file.Required(path, bcl.New())))
	if err != nil {
		return Manifest{}, err
	}

	var blocks []map[string]any
	switch v := mgr.Get("$blocks").(type) {
	case []map[string]any:
		blocks = v
	case []any:
		for _, item := range v {
			if bm, ok := item.(map[string]any); ok {
				blocks = append(blocks, bm)
			}
		}
	}

	var m Manifest
	for _, b := range blocks {
		// Accept both "plugins" (the manifest's own block keyword) and
		// "plugin" (what bcl.Marshal emits for a `bcl:"plugins,block"`
		// tag, since it singularizes plural collection tags for the
		// generated block keyword — see TestMarshalUnmarshalPluralBlockTagUsesSingularBlocks
		// in the bcl package) so hand-authored and Marshal-generated
		// manifests both load correctly.
		t, _ := b["type"].(string)
		if t != "plugins" && t != "plugin" {
			continue
		}
		name, _ := b["id"].(string)
		body, _ := b["body"].(map[string]any)
		enabled, _ := body["enabled"].(bool)
		cfg, _ := body["config"].(map[string]any)
		m.Plugins = append(m.Plugins, PluginSpec{Name: name, Enabled: enabled, Config: cfg})
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
		case json.Number: // github.com/oarkflow/config decodes numbers as json.Number
			if i, err := n.Int64(); err == nil {
				return int(i)
			}
		case float64: // encoding/json decodes JSON numbers as float64
			return int(n)
		case int:
			return n
		case int64:
			return int(n)
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
		case json.Number:
			if i, err := d.Int64(); err == nil {
				return time.Duration(i)
			}
		case float64:
			return time.Duration(d)
		}
	}
	return def
}

var _ api.ConfigProvider = (*config)(nil)
var _ api.PluginConfig = (*pluginConfig)(nil)
