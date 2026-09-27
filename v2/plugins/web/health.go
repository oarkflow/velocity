package web

import (
	"encoding/json"
	"net/http"

	"github.com/oarkflow/velocity/v2/api"
)

// healthChecker is satisfied by any concrete service this plugin holds a
// reference to that also happens to implement api.Plugin's Health()
// method — which in practice is every plugin-backed service looked up in
// Init, since the registered value under a service name is typically the
// concrete plugin itself. Defined structurally (not via api.Plugin
// directly) so this package doesn't need a kernel-wide "list every booted
// plugin" API that doesn't exist today — readyz's scope is deliberately
// "every dependency THIS gateway itself knows about and holds a live
// reference to", not "the entire kernel", which is the most this package
// can honestly check without a wider architectural change.
type healthChecker interface {
	Health() api.Health
}

// dependencyHealth returns Health() for every non-nil optional/required
// service this plugin looked up in Init that happens to implement
// healthChecker. A service that isn't configured (nil field) is simply
// absent from the result, not reported as unhealthy — /readyz only
// judges what's actually wired up.
func (p *Plugin) dependencyHealth() map[string]api.Health {
	out := make(map[string]api.Health)
	check := func(name string, v any) {
		if v == nil {
			return
		}
		if hc, ok := v.(healthChecker); ok {
			out[name] = hc.Health()
		}
	}
	check("kv", p.kv)
	check("object", p.object)
	check("auth", p.auth)
	check("metrics", p.metrics)
	check("auth.oidc", p.oidcAuth)
	check("auth.ldap", p.ldapAuth)
	if p.sts != nil {
		check("auth.sts", p.sts)
	}
	check("mfa", p.mfa)
	check("notifications", p.notifications)
	check("compliance", p.compliance)
	check("search.graph", p.graph)
	check("iam", p.iam)
	return out
}

// handleHealthz is a liveness probe: it reports 200 as long as this
// plugin's own HTTP server is up enough to answer the request at all. It
// deliberately does NOT check any other plugin — that's /readyz's job.
// An orchestrator should restart the process if this ever fails to
// respond at all (timeout/connection-refused), not based on its body.
func (p *Plugin) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// handleReadyz is a readiness probe: 200 only if every dependency this
// gateway holds a live reference to reports Health().Status == "ok"; 503
// with a JSON body naming which dependency is unhealthy otherwise. An
// orchestrator should stop routing traffic here (but not necessarily
// restart the process) while this reports 503.
func (p *Plugin) handleReadyz(w http.ResponseWriter, r *http.Request) {
	healths := p.dependencyHealth()
	unhealthy := make(map[string]api.Health)
	for name, h := range healths {
		if h.Status != "ok" {
			unhealthy[name] = h
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if len(unhealthy) > 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{
			"status":    "unhealthy",
			"unhealthy": unhealthy,
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status":       "ok",
		"dependencies": healths,
	})
}
