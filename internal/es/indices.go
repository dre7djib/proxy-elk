package es

import (
	"path"
	"strings"
)

// indicesFromPath extracts the comma-separated index/alias names named at
// the start of an Elasticsearch request path. A meta endpoint with no
// named index ("/_search", "/_bulk", "/_cat/indices"...) returns nil: the
// caller gets no free pass to a cluster-wide read or write just because
// Decide can't name an index to check (F16's fail-closed spirit).
func indicesFromPath(p string) []string {
	p = strings.TrimPrefix(path.Clean(p), "/")
	if p == "" || p == "." {
		return nil
	}
	first := p
	if i := strings.IndexByte(p, '/'); i >= 0 {
		first = p[:i]
	}
	if first == "" || strings.HasPrefix(first, "_") {
		return nil
	}
	return strings.Split(first, ",")
}
