package esql

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// EnrichClient looks up ENRICH policies on a cluster via
// GET /_enrich/policy/{name}. It authenticates with an API key (same as
// acl.ESResolver), never as the end user — the proxy must resolve policies
// before monitor_enrich is granted to teams.
type EnrichClient struct {
	URL        string
	APIKey     string
	HTTPClient *http.Client
}

// SourceIndices returns the source indices of policy. A missing policy or
// empty indices list is an error (fail-closed).
func (c *EnrichClient) SourceIndices(ctx context.Context, policy string) ([]string, error) {
	if c == nil || c.URL == "" {
		return nil, fmt.Errorf("enrich client not configured")
	}
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	u := strings.TrimRight(c.URL, "/") + "/_enrich/policy/" + url.PathEscape(policy)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if c.APIKey != "" {
		req.Header.Set("Authorization", "ApiKey "+c.APIKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var out struct {
		Policies []struct {
			Config map[string]json.RawMessage `json:"config"`
		} `json:"policies"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Policies) == 0 {
		return nil, fmt.Errorf("not found")
	}
	var indices []string
	seen := map[string]struct{}{}
	for _, pol := range out.Policies {
		for _, raw := range pol.Config {
			var body struct {
				Indices any `json:"indices"`
			}
			if json.Unmarshal(raw, &body) != nil {
				continue
			}
			for _, name := range coerceStringList(body.Indices) {
				if _, ok := seen[name]; ok {
					continue
				}
				seen[name] = struct{}{}
				indices = append(indices, name)
			}
		}
	}
	if len(indices) == 0 {
		return nil, fmt.Errorf("no source indices")
	}
	return indices, nil
}

func coerceStringList(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		var out []string
		for _, e := range t {
			s, ok := e.(string)
			if !ok || s == "" {
				continue
			}
			out = append(out, s)
		}
		return out
	case []string:
		return t
	default:
		return nil
	}
}
