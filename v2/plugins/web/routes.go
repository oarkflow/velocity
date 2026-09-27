package web

import (
	"fmt"
	"net/http"
)

// routeTable builds the HTTP mux while asserting that no method+pattern
// pair is ever registered twice. v1's pkg/web/http_server.go registered
// POST /api/put, GET /api/get/:key, and DELETE /api/delete/:key TWICE,
// verbatim — a real, confirmed bug. This type exists specifically so that
// class of mistake becomes a hard build/test-time error in v2 instead of
// a silent duplicate registration.
type routeTable struct {
	mux         *http.ServeMux
	seen        map[string]bool
	registerErr error
}

func newRouteTable() *routeTable {
	return &routeTable{mux: http.NewServeMux(), seen: make(map[string]bool)}
}

// handle registers pattern (a Go 1.22+ ServeMux pattern, e.g. "GET /api/kv/{key}")
// exactly once. A second registration of the same method+path is a
// programmer error and is surfaced by recording the first error hit,
// checked via err() after all routes are registered.
func (t *routeTable) handle(pattern string, h http.HandlerFunc) {
	if t.seen[pattern] {
		if t.registerErr == nil {
			t.registerErr = fmt.Errorf("web: route %q registered more than once", pattern)
		}
		return
	}
	t.seen[pattern] = true
	t.mux.HandleFunc(pattern, h)
}

// err returns the first duplicate-registration error encountered, if any.
func (t *routeTable) err() error { return t.registerErr }

// patterns returns every distinct method+pattern registered, for tests
// that want to assert on the full route list.
func (t *routeTable) patterns() []string {
	out := make([]string, 0, len(t.seen))
	for p := range t.seen {
		out = append(out, p)
	}
	return out
}
