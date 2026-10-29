package acl

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// IndexResolver turns index/alias names into the concrete index names they
// cover (F15). Deciding on aliases would let a rule written for an alias
// silently cover whatever index it points to; ACL always decides on
// resolved, concrete names.
type IndexResolver interface {
	Resolve(ctx context.Context, names []string) ([]string, error)
}

// ESResolver resolves names against a real cluster's GET
// /_resolve/index/{name} API.
type ESResolver struct {
	URL        string
	APIKey     string
	HTTPClient *http.Client
}

// NewESResolver returns an ESResolver for the given cluster URL and API key.
func NewESResolver(clusterURL, apiKey string) *ESResolver {
	return &ESResolver{URL: clusterURL, APIKey: apiKey}
}

type resolveIndexResponse struct {
	Indices []struct {
		Name string `json:"name"`
	} `json:"indices"`
	Aliases []struct {
		Name    string   `json:"name"`
		Indices []string `json:"indices"`
	} `json:"aliases"`
}

// Resolve fetches /_resolve/index/{names} and returns every concrete index
// name it covers: the indices answer verbatim, plus each alias's member
// indices (never the alias name itself).
func (r *ESResolver) Resolve(ctx context.Context, names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	client := r.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	u := strings.TrimRight(r.URL, "/") + "/_resolve/index/" + url.PathEscape(strings.Join(names, ","))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "ApiKey "+r.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("resolve index: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("resolve index: status %d", resp.StatusCode)
	}

	var out resolveIndexResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("resolve index: %w", err)
	}

	seen := make(map[string]struct{})
	var concrete []string
	add := func(name string) {
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		concrete = append(concrete, name)
	}
	for _, idx := range out.Indices {
		add(idx.Name)
	}
	for _, alias := range out.Aliases {
		for _, idx := range alias.Indices {
			add(idx)
		}
	}
	return concrete, nil
}
