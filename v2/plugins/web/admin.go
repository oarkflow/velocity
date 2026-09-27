package web

import (
	"embed"
	"html/template"
	"net/http"
	"sort"
	"time"
)

//go:embed admin.html
var adminHTMLFS embed.FS

var adminTemplate = template.Must(template.ParseFS(adminHTMLFS, "admin.html"))

// adminPluginRow is one row of the /admin dashboard's plugin table,
// flattened from api.Health for template rendering (html/template needs
// a concrete field, not a map value, to range over predictably-ordered
// data — see the sort below).
type adminPluginRow struct {
	Name   string
	Status string
	Detail string
}

type adminPageData struct {
	PluginCount int
	Uptime      string
	HasMetrics  bool
	Plugins     []adminPluginRow
}

// handleAdminRedirect sends /admin/ to the canonical /admin — both are
// registered so either is a reasonable thing to type/link, but there's
// only one real route (avoids a second near-identical handler to keep in
// sync with the first).
func (p *Plugin) handleAdminRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin", http.StatusMovedPermanently)
}

// handleAdmin renders a single self-contained HTML status page: every
// dependency this gateway holds a live reference to (the SAME set
// /readyz already reports on, via dependencyHealth — deliberately not a
// second, parallel health-collection mechanism), current uptime, and a
// link to /metrics when a metrics plugin is configured. Auth-gated by the
// same p.wrap(...) every other route uses — see buildMux.
func (p *Plugin) handleAdmin(w http.ResponseWriter, r *http.Request) {
	healths := p.dependencyHealth()
	rows := make([]adminPluginRow, 0, len(healths))
	for name, h := range healths {
		rows = append(rows, adminPluginRow{Name: name, Status: h.Status, Detail: h.Detail})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })

	uptime := "unknown"
	if !p.startTime.IsZero() {
		uptime = time.Since(p.startTime).Round(time.Second).String()
	}

	data := adminPageData{
		PluginCount: len(rows),
		Uptime:      uptime,
		HasMetrics:  p.metrics != nil,
		Plugins:     rows,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := adminTemplate.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
