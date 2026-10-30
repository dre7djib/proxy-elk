package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"proxy/internal/config"
)

const testSessionSecret = "01234567890123456789012345678901"

// minimalACL is appended to test configs that don't exercise ACL specifics
// but need buildMux/config.Load to succeed now that acl.rules is mandatory.
const minimalACL = `
acl:
  rules:
    - name: default
      groups: [testers]
      indices: ["*"]
      actions: [read]
`

func baseConfig() *config.Config {
	cfg, _, err := config.Load(writeTestConfig(`
listen: ":0"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
`+minimalACL))
	if err != nil {
		panic(err)
	}
	return cfg
}

func writeTestConfig(body string) string {
	f, err := os.CreateTemp("", "proxy-*.yaml")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.WriteString(body); err != nil {
		panic(err)
	}
	return f.Name()
}

func TestBuildMuxDeniesUnknownRoutesByDefault(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	cfg := baseConfig()
	mux, err := buildMux(cfg)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/anything", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}

	// /auth/me is always registered and must reject (401), not fall
	// through to the catch-all 403.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/me", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/auth/me status = %d", rec.Code)
	}
}

func TestBuildMuxHealthAndMetrics(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	cfg := baseConfig()
	mux, err := buildMux(cfg)
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/health", "/healthz"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d", path, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "go_") && !strings.Contains(body, "process_") {
		t.Fatalf("/metrics body missing go_/process_ metrics: %s", body)
	}

	// Still denied: unknown routes aren't accidentally opened by the health/metrics wiring.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/anything-else", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("/anything-else status = %d", rec.Code)
	}
}

func TestBuildMuxWiresLDAPRoute(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	t.Setenv("LDAP_BIND_PASSWORD", "x")
	t.Setenv("SESSION_SECRET", testSessionSecret)
	cfg, _, err := config.Load(writeTestConfig(`
listen: ":0"
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
`+minimalACL))
	if err != nil {
		t.Fatal(err)
	}

	mux, err := buildMux(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// A malformed body hits LDAPLogin.HandleLogin itself (400), proving the
	// route is wired rather than caught by the "/" 403 default. This never
	// dials the directory.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/ldap", strings.NewReader("not json"))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestBuildMuxWiresOIDCRoutes(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	t.Setenv("OIDC_SECRET", "idp-secret")
	t.Setenv("SESSION_SECRET", testSessionSecret)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
			"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "n": n, "e": e}}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	issuer = srv.URL

	cfg, _, err := config.Load(writeTestConfig(`
listen: ":0"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
oidc:
  issuer: ` + issuer + `
  client_id: proxy
  client_secret: "${env:OIDC_SECRET}"
  redirect_url: https://proxy.example/callback
session:
  secret: "${env:SESSION_SECRET}"
`+minimalACL))
	if err != nil {
		t.Fatal(err)
	}

	built, err := buildMux(cfg)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	built.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("/auth/login status = %d body=%s", rec.Code, rec.Body.String())
	}

	// Missing state cookie/params: 400 from OIDCLogin.HandleCallback, not
	// the "/" 403 default.
	rec = httptest.NewRecorder()
	built.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("/auth/callback status = %d", rec.Code)
	}
}

func TestBuildMuxCatchAllStaysForbiddenUnderQuota(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "k1"
	jwksSrv := http.NewServeMux()
	jwksSrv.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": kid, "n": n, "e": e}}})
	})
	srv := httptest.NewServer(jwksSrv)
	defer srv.Close()

	cfg, _, err := config.Load(writeTestConfig(`
listen: ":0"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
jwt:
  issuer: https://idp.example
  audience: proxy-m2m
  jwks_url: ` + srv.URL + `/jwks
` + minimalACL + `
limits:
  default:
    max_duration: 30s
    max_result_bytes: 1048576
    requests_per_minute: 120
`))
	if err != nil {
		t.Fatal(err)
	}

	built, err := buildMux(cfg)
	if err != nil {
		t.Fatal(err)
	}

	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{
		"iss": "https://idp.example", "sub": "svc-1", "aud": "proxy-m2m",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	built.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, authenticated caller under quota should still get the catch-all 403", rec.Code)
	}
}

func TestBuildMuxWiresJWTBearerOnAuthMe(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "k1"
	jwksSrv := http.NewServeMux()
	jwksSrv.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": kid, "n": n, "e": e}}})
	})
	srv := httptest.NewServer(jwksSrv)
	defer srv.Close()

	cfg, _, err := config.Load(writeTestConfig(`
listen: ":0"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
jwt:
  issuer: https://idp.example
  audience: proxy-m2m
  jwks_url: ` + srv.URL + `/jwks
`+minimalACL))
	if err != nil {
		t.Fatal(err)
	}

	built, err := buildMux(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// No route to mint a JWT exists: the proxy only ever verifies one an
	// external IdP already issued (guard against F78 confusion).
	rec := httptest.NewRecorder()
	built.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/jwt", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("/auth/jwt status = %d, want the catch-all 403 (no such route)", rec.Code)
	}

	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{
		"iss": "https://idp.example", "sub": "svc-1", "aud": "proxy-m2m",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	built.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/auth/me status = %d body=%s", rec.Code, rec.Body.String())
	}
}
