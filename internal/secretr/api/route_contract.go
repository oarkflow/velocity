package api

import "sort"

// RouteMethod defines a concrete method/path contract exposed by the API server.
type RouteMethod struct {
	Method string
	Path   string
}

func RouteMethodContract() []RouteMethod {
	s := NewServer(Config{Address: ":0"})
	routes := s.RouteMethods()
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path == routes[j].Path {
			return routes[i].Method < routes[j].Method
		}
		return routes[i].Path < routes[j].Path
	})
	return routes
}
