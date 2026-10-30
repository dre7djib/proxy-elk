package acl

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		method, path string
		want         Action
	}{
		{"GET", "/logs-a/_search", ActionRead},
		{"HEAD", "/logs-a", ActionRead},
		{"POST", "/logs-a/_search", ActionRead},
		{"POST", "/logs-a/_msearch", ActionRead},
		{"POST", "/logs-a/_count", ActionRead},
		{"POST", "/logs-a/_field_caps", ActionRead},
		{"POST", "/logs-a/_validate/query", ActionRead},
		{"POST", "/logs-a/_async_search", ActionRead},
		{"POST", "/logs-a/_doc", ActionWrite},
		{"PUT", "/logs-a/_doc/1", ActionWrite},
		{"DELETE", "/logs-a/_doc/1", ActionWrite},
		{"GET", "/_cluster/health", ActionClusterAdmin},
		{"GET", "/_security/user", ActionClusterAdmin},
		{"GET", "/_nodes/stats", ActionClusterAdmin},
		{"GET", "/_license", ActionClusterAdmin},
		{"GET", "/_snapshot/repo", ActionClusterAdmin},
		{"GET", "/_slm/policy", ActionClusterAdmin},
		{"GET", "/_tasks", ActionClusterAdmin},
		{"GET", "/_cat/indices", ActionClusterAdmin},
		{"POST", "/_security/user/alice/_password", ActionClusterAdmin},
	}
	for _, c := range cases {
		if got := Classify(c.method, c.path); got != c.want {
			t.Errorf("Classify(%q, %q) = %q, want %q", c.method, c.path, got, c.want)
		}
	}
}
