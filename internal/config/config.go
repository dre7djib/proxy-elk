// Package config loads YAML configuration and resolves secret references.
package config

import (
	"proxy/internal/acl"
	"proxy/internal/limits"
)

// Config is the process configuration. Secret fields hold resolved values.
type Config struct {
	Listen        string        `yaml:"listen" json:"listen"`
	Elasticsearch Elasticsearch `yaml:"elasticsearch" json:"elasticsearch"`
	OIDC          OIDC          `yaml:"oidc" json:"oidc"`
	LDAP          LDAP          `yaml:"ldap" json:"ldap"`
	JWT           JWT           `yaml:"jwt" json:"jwt"`
	ACL           ACL           `yaml:"acl" json:"acl"`
	Limits        Limits        `yaml:"limits" json:"limits"`
	Session       Session       `yaml:"session" json:"session"`
	Kibana        Kibana        `yaml:"kibana" json:"kibana"`
	Kerberos      Kerberos      `yaml:"kerberos" json:"kerberos"`

	secrets secretSet
}

// Limits is the optional per-role quota section (F25): absent (Default
// nil and Roles empty) means no plafond at all, same as today. Roles
// matches the caller's groups against a quota; Default applies when no
// role matches. See internal/limits for how they're combined.
type Limits struct {
	Default *limits.Role  `yaml:"default" json:"default"`
	Roles   []limits.Role `yaml:"roles" json:"roles"`
}

// ACL is the declarative, read-only access policy (F14/F19): a non-empty
// set of allow rules, fail-closed otherwise. KnownGroups, when set,
// restricts which groups rules may reference. SystemIndices overrides the
// F17 default system index patterns.
type ACL struct {
	KnownGroups   []string   `yaml:"known_groups" json:"known_groups"`
	SystemIndices []string   `yaml:"system_indices" json:"system_indices"`
	Rules         []acl.Rule `yaml:"rules" json:"rules"`
}

// Elasticsearch is the upstream cluster. APIKey resolves the ACL index
// resolver's own calls (/_resolve/index); it is never sent on the relayed
// request. RunAsPassword and ShadowPassword come from a secret reference.
type Elasticsearch struct {
	URL    string `yaml:"url" json:"url"`
	APIKey string `yaml:"api_key" json:"api_key"`

	// RunAsUser/RunAsPassword is the service account the relay
	// authenticates as upstream once a caller's identity is resolved and
	// allowed; es-security-runas-user then impersonates that caller (F2).
	RunAsUser     string `yaml:"run_as_user" json:"run_as_user"`
	RunAsPassword string `yaml:"run_as_password" json:"run_as_password"`
	// ShadowPassword is the native-realm secret substituted into
	// POST /_security/profile/_activate for an LDAP user, once their LDAP
	// password has been re-checked (F2): never typed by the user, never
	// sent to LDAP.
	ShadowPassword string `yaml:"shadow_password" json:"shadow_password"`
	// PassthroughUsers relay unchanged, with their own Basic credentials,
	// never through the ACL. Defaults to [kibana_system].
	PassthroughUsers []string `yaml:"passthrough_users" json:"passthrough_users"`
}

// Kibana enables the SSO login bridge (/auth/kibana): the proxy logs the
// browser into Kibana's own session on its behalf (POST
// /internal/security/login) right after an LDAP login, so Kibana's own
// login screen never appears. Empty URL disables the route. URL is the
// address the proxy itself calls (container-internal, e.g.
// http://kibana:5601); PublicURL is where the browser is redirected
// afterwards (e.g. http://127.0.0.1:5601) and defaults to URL when empty.
type Kibana struct {
	URL       string `yaml:"url" json:"url"`
	PublicURL string `yaml:"public_url" json:"public_url"`
}

// Kerberos enables SPNEGO/Negotiate login in place of the /auth/kibana
// form: the browser never types a password, the proxy validates the
// ticket against KeytabFile (a mounted binary file, never a ${file:}
// secret reference — that would land it in the secret mask) and resolves
// groups via LDAP (required alongside, since Kerberos carries none
// itself). Empty KeytabFile disables the whole path.
type Kerberos struct {
	KeytabFile       string `yaml:"keytab_file" json:"keytab_file"`
	ServicePrincipal string `yaml:"service_principal" json:"service_principal"`
	Realm            string `yaml:"realm" json:"realm"`
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

// JWT configures verification of machine-to-machine Bearer tokens (F13):
// the proxy checks a JWT an external IdP already issued, it never emits
// one. Empty Issuer means JWT Bearer auth is disabled; no session cookie
// is involved.
type JWT struct {
	Issuer   string `yaml:"issuer" json:"issuer"`
	Audience string `yaml:"audience" json:"audience"`
	JWKSURL  string `yaml:"jwks_url" json:"jwks_url"`
	// GroupsClaim is the token claim holding the caller's groups. Defaults to "groups".
	GroupsClaim string `yaml:"groups_claim" json:"groups_claim"`
}

// Session configures the HMAC-signed login session shared by OIDC and
// LDAP. Secret comes from a secret reference and must be at least 32
// bytes. Required as soon as OIDC or LDAP is active.
type Session struct {
	Secret string `yaml:"secret" json:"secret"`
	// TTL is a Go duration string (e.g. "8h"). Defaults to 8h.
	TTL string `yaml:"ttl" json:"ttl"`
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
