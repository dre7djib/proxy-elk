package acl

import "strings"

// clusterAdminPrefixes are path prefixes Classify treats as cluster_admin
// (F18) regardless of HTTP method: these are administrative/informational
// endpoints, not data reads, even when fetched with GET.
var clusterAdminPrefixes = []string{
	"/_cluster", "/_security", "/_nodes", "/_license", "/_snapshot", "/_slm", "/_tasks", "/_cat",
}

// readPOSTSuffixes are path suffixes that make a POST a read (search-style
// requests that don't fit GET because they carry a body).
var readPOSTSuffixes = []string{
	"/_search", "/_msearch", "/_count", "/_field_caps", "/_validate/query", "/_async_search",
}

// Classify derives the Action an upstream Elasticsearch request
// represents from its HTTP method and path (F18). Only ActionRead can
// ever be granted by a rule (Parse rejects any other action in YAML), so
// a write or cluster_admin request is always denied by Decide regardless
// of index coverage.
func Classify(method, path string) Action {
	for _, prefix := range clusterAdminPrefixes {
		if strings.HasPrefix(path, prefix) {
			return ActionClusterAdmin
		}
	}
	switch method {
	case "GET", "HEAD":
		return ActionRead
	case "POST":
		for _, suffix := range readPOSTSuffixes {
			if strings.HasSuffix(path, suffix) {
				return ActionRead
			}
		}
	}
	return ActionWrite
}
