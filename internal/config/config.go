// Package config loads YAML configuration and resolves secret references.
package config

// Config is the process configuration. Secret fields hold resolved values.
type Config struct {
	Listen        string        `yaml:"listen" json:"listen"`
	Elasticsearch Elasticsearch `yaml:"elasticsearch" json:"elasticsearch"`
	OIDC          OIDC          `yaml:"oidc" json:"oidc"`
	LDAP          LDAP          `yaml:"ldap" json:"ldap"`

	secrets secretSet
}

// Elasticsearch is the upstream cluster. APIKey comes from a secret reference.
type Elasticsearch struct {
	URL    string `yaml:"url" json:"url"`
	APIKey string `yaml:"api_key" json:"api_key"`
}

// OIDC is the identity provider used for the authorization code flow.
// ClientSecret comes from a secret reference. Empty Issuer means OIDC login
// is disabled.
type OIDC struct {
	Issuer       string   `yaml:"issuer" json:"issuer"`
	ClientID     string   `yaml:"client_id" json:"client_id"`
	ClientSecret string   `yaml:"client_secret" json:"client_secret"`
	RedirectURL  string   `yaml:"redirect_url" json:"redirect_url"`
	Scopes       []string `yaml:"scopes" json:"scopes"`
	// GroupsClaim is the ID token claim holding the user's groups. Defaults to "groups".
	GroupsClaim string `yaml:"groups_claim" json:"groups_claim"`
}

// LDAP is the directory used for search-then-bind authentication.
// BindPassword comes from a secret reference. Empty URL and URLs means LDAP
// login is disabled.
type LDAP struct {
	// URL is a single directory address. Mutually exclusive with URLs; use
	// URLs instead to list several addresses for failover.
	URL      string   `yaml:"url" json:"url"`
	URLs     []string `yaml:"urls" json:"urls"`
	StartTLS bool     `yaml:"start_tls" json:"start_tls"`

	BindDN       string `yaml:"bind_dn" json:"bind_dn"`
	BindPassword string `yaml:"bind_password" json:"bind_password"`
	BaseDN       string `yaml:"base_dn" json:"base_dn"`
	// UserFilter is the search filter used to find the user's DN. It must
	// contain exactly one %s, replaced with the escaped username.
	UserFilter   string `yaml:"user_filter" json:"user_filter"`
	GroupsBaseDN string `yaml:"groups_base_dn" json:"groups_base_dn"`
	CAFile       string `yaml:"ca_file" json:"ca_file"`
	// InsecureAllowPlaintext allows ldap:// without start_tls. Dev only.
	InsecureAllowPlaintext bool `yaml:"insecure_allow_plaintext" json:"insecure_allow_plaintext"`

	// NestedGroups resolves Active Directory nested group membership via the
	// LDAP_MATCHING_RULE_IN_CHAIN OID instead of a flat groupOfNames search.
	NestedGroups bool `yaml:"nested_groups" json:"nested_groups"`
	// GroupCacheTTL is a Go duration string (e.g. "5m"). Defaults to 5m.
	GroupCacheTTL string `yaml:"group_cache_ttl" json:"group_cache_ttl"`

	// MaxFailures is the number of failed logins for a (user, IP) pair
	// within FailureWindow before it is locked out for LockoutFor. Defaults
	// to 5.
	MaxFailures int `yaml:"max_failures" json:"max_failures"`
	// FailureWindow and LockoutFor are Go duration strings. Default to 15m.
	FailureWindow string `yaml:"failure_window" json:"failure_window"`
	LockoutFor    string `yaml:"lockout_for" json:"lockout_for"`
}

// Warning is a non-fatal configuration problem, such as a world-readable secret file.
type Warning struct {
	Message string
}

func (w Warning) String() string { return w.Message }

type secretSet struct {
	paths  map[string]struct{}
	values []string
}

func (s *secretSet) add(path, value string) {
	if s.paths == nil {
		s.paths = map[string]struct{}{}
	}
	s.paths[path] = struct{}{}
	s.values = append(s.values, value)
}
