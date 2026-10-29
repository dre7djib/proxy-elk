package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadEnvResolvesAndRedacts(t *testing.T) {
	const secret = "super-secret-value"
	t.Setenv("ES_API_KEY", secret)
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
`)
	cfg, warnings, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
	if cfg.Listen != ":8080" || cfg.Elasticsearch.URL != "https://elasticsearch:9200" {
		t.Fatalf("literals changed: %+v", cfg.Redacted())
	}
	if cfg.Elasticsearch.APIKey != secret {
		t.Fatalf("api key = %q", cfg.Elasticsearch.APIKey)
	}

	red := cfg.Redacted()
	if red.Elasticsearch.APIKey != "***" {
		t.Fatalf("redacted api key = %q", red.Elasticsearch.APIKey)
	}
	if red.Listen != ":8080" {
		t.Fatalf("redacted listen = %q", red.Listen)
	}
	b, err := json.Marshal(red)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), secret) {
		t.Fatalf("redacted json leaked secret: %s", b)
	}
	masked := cfg.Mask("token=" + secret + " end")
	if strings.Contains(masked, secret) || masked != "token=*** end" {
		t.Fatalf("mask = %q", masked)
	}
}

func TestLoadMissingEnv(t *testing.T) {
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY_ABSENT}"
`)
	_, _, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "secret env:ES_API_KEY_ABSENT missing") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadFileSecret(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "api_key")
	if err := os.WriteFile(keyPath, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${file:`+keyPath+`}"
`)
	cfg, warnings, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
	if cfg.Elasticsearch.APIKey != "file-secret" {
		t.Fatalf("api key = %q", cfg.Elasticsearch.APIKey)
	}
	if strings.Contains(cfg.Mask("x=file-secret"), "file-secret") {
		t.Fatal("mask leaked file secret")
	}
}

func TestLoadWorldReadableFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "api_key")
	if err := os.WriteFile(keyPath, []byte("file-secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${file:`+keyPath+`}"
`)
	cfg, warnings, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Elasticsearch.APIKey != "file-secret" {
		t.Fatalf("api key = %q", cfg.Elasticsearch.APIKey)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0].Message, "world-readable") {
		t.Fatalf("warnings = %v", warnings)
	}
	if strings.Contains(warnings[0].Message, "file-secret") {
		t.Fatalf("warning leaked secret: %s", warnings[0].Message)
	}
}

func TestLoadMissingFile(t *testing.T) {
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${file:/no/such/secret}"
`)
	_, _, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "secret file:/no/such/secret missing") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadEmptyFileSecret(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "api_key")
	if err := os.WriteFile(keyPath, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${file:`+keyPath+`}"
`)
	_, _, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadRejectsPlaintextAPIKey(t *testing.T) {
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "plaintext-key"
`)
	_, _, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "elasticsearch.api_key") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadOIDCRequiresClientSecret(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
oidc:
  issuer: https://idp.example
  client_id: proxy
  redirect_url: https://proxy.example/callback
  client_secret: "plaintext"
`)
	_, _, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "oidc.client_secret") {
		t.Fatalf("err = %v", err)
	}
}

const testSessionSecret = "01234567890123456789012345678901"

func TestLoadOIDCResolvesSecret(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	t.Setenv("OIDC_SECRET", "idp-secret")
	t.Setenv("SESSION_SECRET", testSessionSecret)
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
oidc:
  issuer: https://idp.example
  client_id: proxy
  redirect_url: https://proxy.example/callback
  client_secret: "${env:OIDC_SECRET}"
session:
  secret: "${env:SESSION_SECRET}"
`)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.ClientSecret != "idp-secret" {
		t.Fatalf("client secret = %q", cfg.OIDC.ClientSecret)
	}
	if strings.Contains(cfg.Mask("x="+cfg.OIDC.ClientSecret), cfg.OIDC.ClientSecret) {
		t.Fatal("mask leaked oidc client secret")
	}
}

func TestLoadLDAPRejectsPlaintextWithoutStartTLS(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	t.Setenv("LDAP_BIND_PASSWORD", "x")
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
ldap:
  url: ldap://ldap.example:389
  bind_dn: "cn=readonly,dc=example,dc=org"
  bind_password: "${env:LDAP_BIND_PASSWORD}"
  base_dn: "ou=people,dc=example,dc=org"
  user_filter: "(uid=%s)"
  groups_base_dn: "ou=groups,dc=example,dc=org"
`)
	_, _, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "plaintext") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadLDAPAllowsStartTLS(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	t.Setenv("LDAP_BIND_PASSWORD", "x")
	t.Setenv("SESSION_SECRET", testSessionSecret)
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
ldap:
  url: ldap://ldap.example:389
  start_tls: true
  bind_dn: "cn=readonly,dc=example,dc=org"
  bind_password: "${env:LDAP_BIND_PASSWORD}"
  base_dn: "ou=people,dc=example,dc=org"
  user_filter: "(uid=%s)"
  groups_base_dn: "ou=groups,dc=example,dc=org"
session:
  secret: "${env:SESSION_SECRET}"
`)
	if _, _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}

func TestLoadLDAPAllowsExplicitPlaintext(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	t.Setenv("LDAP_BIND_PASSWORD", "x")
	t.Setenv("SESSION_SECRET", testSessionSecret)
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
ldap:
  url: ldap://ldap.example:389
  insecure_allow_plaintext: true
  bind_dn: "cn=readonly,dc=example,dc=org"
  bind_password: "${env:LDAP_BIND_PASSWORD}"
  base_dn: "ou=people,dc=example,dc=org"
  user_filter: "(uid=%s)"
  groups_base_dn: "ou=groups,dc=example,dc=org"
session:
  secret: "${env:SESSION_SECRET}"
`)
	if _, _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}

func TestLoadLDAPAcceptsLDAPS(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	t.Setenv("LDAP_BIND_PASSWORD", "x")
	t.Setenv("SESSION_SECRET", testSessionSecret)
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
ldap:
  url: ldaps://ldap.example:636
  bind_dn: "cn=readonly,dc=example,dc=org"
  bind_password: "${env:LDAP_BIND_PASSWORD}"
  base_dn: "ou=people,dc=example,dc=org"
  user_filter: "(uid=%s)"
  groups_base_dn: "ou=groups,dc=example,dc=org"
session:
  secret: "${env:SESSION_SECRET}"
`)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LDAP.BindPassword != "x" {
		t.Fatalf("bind password = %q", cfg.LDAP.BindPassword)
	}
}

func TestLoadLDAPRequiresBindPasswordSecret(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
ldap:
  url: ldaps://ldap.example:636
  bind_dn: "cn=readonly,dc=example,dc=org"
  bind_password: "plaintext"
  base_dn: "ou=people,dc=example,dc=org"
  user_filter: "(uid=%s)"
  groups_base_dn: "ou=groups,dc=example,dc=org"
`)
	_, _, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "ldap.bind_password") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadLDAPRequiresSingleUserFilterPlaceholder(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	t.Setenv("LDAP_BIND_PASSWORD", "x")
	for _, filter := range []string{"(uid=fixed)", "(uid=%s)(cn=%s)"} {
		path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
ldap:
  url: ldaps://ldap.example:636
  bind_dn: "cn=readonly,dc=example,dc=org"
  bind_password: "${env:LDAP_BIND_PASSWORD}"
  base_dn: "ou=people,dc=example,dc=org"
  user_filter: "`+filter+`"
  groups_base_dn: "ou=groups,dc=example,dc=org"
`)
		_, _, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), "user_filter") {
			t.Fatalf("filter %q: err = %v", filter, err)
		}
	}
}

func TestLoadLDAPDefaults(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	t.Setenv("LDAP_BIND_PASSWORD", "x")
	t.Setenv("SESSION_SECRET", testSessionSecret)
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
ldap:
  url: ldaps://ldap.example:636
  bind_dn: "cn=readonly,dc=example,dc=org"
  bind_password: "${env:LDAP_BIND_PASSWORD}"
  base_dn: "ou=people,dc=example,dc=org"
  user_filter: "(uid=%s)"
  groups_base_dn: "ou=groups,dc=example,dc=org"
session:
  secret: "${env:SESSION_SECRET}"
`)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LDAP.GroupCacheTTL != "5m" || cfg.LDAP.FailureWindow != "15m" || cfg.LDAP.LockoutFor != "15m" || cfg.LDAP.MaxFailures != 5 {
		t.Fatalf("defaults = %+v", cfg.LDAP)
	}
	if cfg.LDAP.NestedGroups {
		t.Fatal("nested_groups should default to false")
	}
	if cfg.Session.TTL != "8h" {
		t.Fatalf("session ttl default = %q", cfg.Session.TTL)
	}
}

func TestLoadLDAPURLsFailover(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	t.Setenv("LDAP_BIND_PASSWORD", "x")
	t.Setenv("SESSION_SECRET", testSessionSecret)
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
ldap:
  urls: [ldaps://dc1.example:636, ldaps://dc2.example:636]
  bind_dn: "cn=readonly,dc=example,dc=org"
  bind_password: "${env:LDAP_BIND_PASSWORD}"
  base_dn: "ou=people,dc=example,dc=org"
  user_filter: "(uid=%s)"
  groups_base_dn: "ou=groups,dc=example,dc=org"
session:
  secret: "${env:SESSION_SECRET}"
`)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.LDAP.URLs) != 2 {
		t.Fatalf("urls = %v", cfg.LDAP.URLs)
	}
}

func TestLoadLDAPRejectsURLAndURLsTogether(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	t.Setenv("LDAP_BIND_PASSWORD", "x")
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
ldap:
  url: ldaps://dc1.example:636
  urls: [ldaps://dc1.example:636, ldaps://dc2.example:636]
  bind_dn: "cn=readonly,dc=example,dc=org"
  bind_password: "${env:LDAP_BIND_PASSWORD}"
  base_dn: "ou=people,dc=example,dc=org"
  user_filter: "(uid=%s)"
  groups_base_dn: "ou=groups,dc=example,dc=org"
`)
	_, _, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "either ldap.url or ldap.urls") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadLDAPRejectsInvalidDurations(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	t.Setenv("LDAP_BIND_PASSWORD", "x")
	for _, field := range []string{"group_cache_ttl: not-a-duration", "failure_window: 0s", "lockout_for: -5m"} {
		path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
ldap:
  url: ldaps://ldap.example:636
  bind_dn: "cn=readonly,dc=example,dc=org"
  bind_password: "${env:LDAP_BIND_PASSWORD}"
  base_dn: "ou=people,dc=example,dc=org"
  user_filter: "(uid=%s)"
  groups_base_dn: "ou=groups,dc=example,dc=org"
  `+field+`
`)
		_, _, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), "positive Go duration") {
			t.Fatalf("field %q: err = %v", field, err)
		}
	}
}

func TestLoadLDAPRejectsMaxFailuresBelowOne(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	t.Setenv("LDAP_BIND_PASSWORD", "x")
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
ldap:
  url: ldaps://ldap.example:636
  bind_dn: "cn=readonly,dc=example,dc=org"
  bind_password: "${env:LDAP_BIND_PASSWORD}"
  base_dn: "ou=people,dc=example,dc=org"
  user_filter: "(uid=%s)"
  groups_base_dn: "ou=groups,dc=example,dc=org"
  max_failures: -1
`)
	_, _, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "max_failures") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadRequiresSessionSecretWhenOIDCActive(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	t.Setenv("OIDC_SECRET", "idp-secret")
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
oidc:
  issuer: https://idp.example
  client_id: proxy
  redirect_url: https://proxy.example/callback
  client_secret: "${env:OIDC_SECRET}"
`)
	_, _, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "session.secret") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadRequiresSessionSecretWhenLDAPActive(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	t.Setenv("LDAP_BIND_PASSWORD", "x")
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
ldap:
  url: ldaps://ldap.example:636
  bind_dn: "cn=readonly,dc=example,dc=org"
  bind_password: "${env:LDAP_BIND_PASSWORD}"
  base_dn: "ou=people,dc=example,dc=org"
  user_filter: "(uid=%s)"
  groups_base_dn: "ou=groups,dc=example,dc=org"
`)
	_, _, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "session.secret") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadRejectsSessionSecretPlaintext(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	t.Setenv("LDAP_BIND_PASSWORD", "x")
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
ldap:
  url: ldaps://ldap.example:636
  bind_dn: "cn=readonly,dc=example,dc=org"
  bind_password: "${env:LDAP_BIND_PASSWORD}"
  base_dn: "ou=people,dc=example,dc=org"
  user_filter: "(uid=%s)"
  groups_base_dn: "ou=groups,dc=example,dc=org"
session:
  secret: "`+testSessionSecret+`"
`)
	_, _, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "session.secret") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadRejectsShortSessionSecret(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	t.Setenv("LDAP_BIND_PASSWORD", "x")
	t.Setenv("SESSION_SECRET", "too-short")
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
ldap:
  url: ldaps://ldap.example:636
  bind_dn: "cn=readonly,dc=example,dc=org"
  bind_password: "${env:LDAP_BIND_PASSWORD}"
  base_dn: "ou=people,dc=example,dc=org"
  user_filter: "(uid=%s)"
  groups_base_dn: "ou=groups,dc=example,dc=org"
session:
  secret: "${env:SESSION_SECRET}"
`)
	_, _, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadRejectsInvalidSessionTTL(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	t.Setenv("LDAP_BIND_PASSWORD", "x")
	t.Setenv("SESSION_SECRET", testSessionSecret)
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
ldap:
  url: ldaps://ldap.example:636
  bind_dn: "cn=readonly,dc=example,dc=org"
  bind_password: "${env:LDAP_BIND_PASSWORD}"
  base_dn: "ou=people,dc=example,dc=org"
  user_filter: "(uid=%s)"
  groups_base_dn: "ou=groups,dc=example,dc=org"
session:
  secret: "${env:SESSION_SECRET}"
  ttl: not-a-duration
`)
	_, _, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "session.ttl") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadSessionOptionalWithoutOIDCOrLDAP(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
`)
	if _, _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}

func TestLoadJWTRequiresAudience(t *testing.T) {
	t.Setenv("ES_API_KEY", "secret")
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
jwt:
  issuer: https://idp.example
  jwks_url: https://idp.example/certs
`)
	if _, _, err := Load(path); err == nil || !strings.Contains(err.Error(), "jwt.audience") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadJWTRequiresJWKSURL(t *testing.T) {
	t.Setenv("ES_API_KEY", "secret")
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
jwt:
  issuer: https://idp.example
  audience: proxy-m2m
`)
	if _, _, err := Load(path); err == nil || !strings.Contains(err.Error(), "jwt.jwks_url") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadJWTOptionalWithoutIssuer(t *testing.T) {
	t.Setenv("ES_API_KEY", "secret")
	path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
`)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.JWT.Issuer != "" {
		t.Fatalf("jwt = %+v", cfg.JWT)
	}
}

func TestLoadMalformedReference(t *testing.T) {
	for _, body := range []string{
		`api_key: "${env:}"`,
		`api_key: "prefix-${env:ES_API_KEY}"`,
		`api_key: "${unknown:X}"`,
	} {
		path := writeConfig(t, `
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  `+body+`
`)
		_, _, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), "malformed secret reference") {
			t.Fatalf("body %s: err = %v", body, err)
		}
	}
}

func TestExampleConfig(t *testing.T) {
	const secret = "example-secret-value"
	t.Setenv("ES_API_KEY", secret)
	t.Setenv("OIDC_CLIENT_SECRET", "example-oidc-secret")
	t.Setenv("LDAP_BIND_PASSWORD", "example-ldap-secret")
	t.Setenv("SESSION_SECRET", testSessionSecret)
	cfg, _, err := Load("../../configs/proxy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Elasticsearch.APIKey != secret {
		t.Fatalf("api key = %q", cfg.Elasticsearch.APIKey)
	}
	if cfg.OIDC.ClientSecret != "example-oidc-secret" {
		t.Fatalf("oidc client secret = %q", cfg.OIDC.ClientSecret)
	}
	if cfg.LDAP.BindPassword != "example-ldap-secret" {
		t.Fatalf("ldap bind password = %q", cfg.LDAP.BindPassword)
	}
	if strings.Contains(cfg.Mask(secret), secret) {
		t.Fatal("mask leaked example secret")
	}
}
