package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load reads path, resolves ${env:NAME} and ${file:PATH} references, and
// returns the configuration. A missing referenced secret is an error.
// Warnings report world-readable secret files; they do not block startup.
func Load(path string) (*Config, []Warning, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, nil, fmt.Errorf("parse config: %w", err)
	}

	var warnings []Warning
	var secrets secretSet
	if err := resolveNode(&root, "", &secrets, &warnings); err != nil {
		return nil, nil, err
	}

	var cfg Config
	if err := root.Decode(&cfg); err != nil {
		return nil, nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.validate(secrets); err != nil {
		return nil, nil, err
	}
	cfg.secrets = secrets
	return &cfg, warnings, nil
}

func (c *Config) validate(secrets secretSet) error {
	if _, ok := secrets.paths["elasticsearch.api_key"]; !ok || c.Elasticsearch.APIKey == "" {
		return fmt.Errorf("elasticsearch.api_key must be ${env:NAME} or ${file:PATH}")
	}
	if c.OIDC.Issuer != "" {
		if c.OIDC.ClientID == "" {
			return fmt.Errorf("oidc.client_id is required when oidc.issuer is set")
		}
		if c.OIDC.RedirectURL == "" {
			return fmt.Errorf("oidc.redirect_url is required when oidc.issuer is set")
		}
		if _, ok := secrets.paths["oidc.client_secret"]; !ok || c.OIDC.ClientSecret == "" {
			return fmt.Errorf("oidc.client_secret must be ${env:NAME} or ${file:PATH}")
		}
	}
	if c.LDAP.URL != "" {
		if c.LDAP.BindDN == "" {
			return fmt.Errorf("ldap.bind_dn is required when ldap.url is set")
		}
		if _, ok := secrets.paths["ldap.bind_password"]; !ok || c.LDAP.BindPassword == "" {
			return fmt.Errorf("ldap.bind_password must be ${env:NAME} or ${file:PATH}")
		}
		if c.LDAP.BaseDN == "" {
			return fmt.Errorf("ldap.base_dn is required when ldap.url is set")
		}
		if strings.Count(c.LDAP.UserFilter, "%s") != 1 {
			return fmt.Errorf("ldap.user_filter must contain exactly one %%s")
		}
		if c.LDAP.GroupsBaseDN == "" {
			return fmt.Errorf("ldap.groups_base_dn is required when ldap.url is set")
		}
		if strings.HasPrefix(c.LDAP.URL, "ldap://") && !c.LDAP.StartTLS && !c.LDAP.InsecureAllowPlaintext {
			return fmt.Errorf("ldap.url is plaintext: use ldaps://, set ldap.start_tls, or ldap.insecure_allow_plaintext for dev")
		}
	}
	return nil
}
