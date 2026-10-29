package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// testProvider runs a fake OIDC provider: discovery, JWKS, authorization and
// token endpoints, signing ID tokens with a freshly generated RSA key.
type testProvider struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	issuer   string
	clientID string
	nextCode string
	claims   map[string]any
}

func newTestProvider(t *testing.T) *testProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tp := &testProvider{key: key, clientID: "proxy-client", nextCode: "good-code"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 tp.issuer,
			"authorization_endpoint": tp.issuer + "/authorize",
			"token_endpoint":         tp.issuer + "/token",
			"jwks_uri":               tp.issuer + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(bigEndianBytes(key.PublicKey.E))
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "test-key", "n": n, "e": e,
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.FormValue("code") != tp.nextCode {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}
		idToken := tp.sign(t, tp.claims)
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": "access-token",
			"id_token":     idToken,
			"token_type":   "Bearer",
		})
	})
	tp.srv = httptest.NewServer(mux)
	tp.issuer = tp.srv.URL
	t.Cleanup(tp.srv.Close)
	return tp
}

func bigEndianBytes(e int) []byte {
	b := []byte{byte(e >> 16), byte(e >> 8), byte(e)}
	i := 0
	for i < len(b)-1 && b[i] == 0 {
		i++
	}
	return b[i:]
}

func (tp *testProvider) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, tp.key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func baseClaims(issuer, clientID, nonce string) map[string]any {
	return map[string]any{
		"iss":    issuer,
		"sub":    "user-123",
		"email":  "alice@example.com",
		"aud":    clientID,
		"nonce":  nonce,
		"exp":    time.Now().Add(time.Hour).Unix(),
		"groups": []string{"team-payments-viewer"},
	}
}

func TestExchangeValidToken(t *testing.T) {
	tp := newTestProvider(t)
	tp.claims = baseClaims(tp.issuer, tp.clientID, "nonce-abc")

	p, err := Discover(context.Background(), OIDCConfig{
		Issuer:       tp.issuer,
		ClientID:     tp.clientID,
		ClientSecret: "secret",
		RedirectURL:  "https://proxy.example/callback",
	})
	if err != nil {
		t.Fatal(err)
	}

	authURL := p.AuthCodeURL("state-1", "nonce-abc")
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("client_id") != tp.clientID || u.Query().Get("nonce") != "nonce-abc" {
		t.Fatalf("auth url = %s", authURL)
	}

	id, err := p.Exchange(context.Background(), "good-code", "nonce-abc")
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "user-123" || id.Email != "alice@example.com" {
		t.Fatalf("identity = %+v", id)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "team-payments-viewer" {
		t.Fatalf("groups = %v", id.Groups)
	}
}

func TestExchangeWrongCode(t *testing.T) {
	tp := newTestProvider(t)
	tp.claims = baseClaims(tp.issuer, tp.clientID, "nonce-abc")
	p, err := Discover(context.Background(), OIDCConfig{
		Issuer: tp.issuer, ClientID: tp.clientID, ClientSecret: "secret", RedirectURL: "https://proxy.example/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exchange(context.Background(), "wrong-code", "nonce-abc"); err == nil {
		t.Fatal("expected error for wrong code")
	}
}

func TestExchangeRejectsNonceMismatch(t *testing.T) {
	tp := newTestProvider(t)
	tp.claims = baseClaims(tp.issuer, tp.clientID, "nonce-abc")
	p, err := Discover(context.Background(), OIDCConfig{
		Issuer: tp.issuer, ClientID: tp.clientID, ClientSecret: "secret", RedirectURL: "https://proxy.example/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exchange(context.Background(), "good-code", "other-nonce"); err == nil {
		t.Fatal("expected nonce mismatch error")
	}
}

func TestExchangeRejectsExpiredToken(t *testing.T) {
	tp := newTestProvider(t)
	tp.claims = baseClaims(tp.issuer, tp.clientID, "nonce-abc")
	tp.claims["exp"] = time.Now().Add(-time.Hour).Unix()
	p, err := Discover(context.Background(), OIDCConfig{
		Issuer: tp.issuer, ClientID: tp.clientID, ClientSecret: "secret", RedirectURL: "https://proxy.example/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exchange(context.Background(), "good-code", "nonce-abc"); err == nil {
		t.Fatal("expected expired token error")
	}
}

func TestExchangeRejectsWrongAudience(t *testing.T) {
	tp := newTestProvider(t)
	tp.claims = baseClaims(tp.issuer, "someone-else", "nonce-abc")
	p, err := Discover(context.Background(), OIDCConfig{
		Issuer: tp.issuer, ClientID: tp.clientID, ClientSecret: "secret", RedirectURL: "https://proxy.example/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exchange(context.Background(), "good-code", "nonce-abc"); err == nil {
		t.Fatal("expected audience mismatch error")
	}
}

func TestExchangeRejectsWrongIssuer(t *testing.T) {
	tp := newTestProvider(t)
	tp.claims = baseClaims("https://attacker.example", tp.clientID, "nonce-abc")
	p, err := Discover(context.Background(), OIDCConfig{
		Issuer: tp.issuer, ClientID: tp.clientID, ClientSecret: "secret", RedirectURL: "https://proxy.example/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exchange(context.Background(), "good-code", "nonce-abc"); err == nil {
		t.Fatal("expected issuer mismatch error")
	}
}

func TestExchangeRejectsBadSignature(t *testing.T) {
	tp := newTestProvider(t)
	tp.claims = baseClaims(tp.issuer, tp.clientID, "nonce-abc")
	p, err := Discover(context.Background(), OIDCConfig{
		Issuer: tp.issuer, ClientID: tp.clientID, ClientSecret: "secret", RedirectURL: "https://proxy.example/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Sign with a different key than the one published in JWKS.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	original := tp.key
	tp.key = otherKey
	defer func() { tp.key = original }()

	if _, err := p.Exchange(context.Background(), "good-code", "nonce-abc"); err == nil {
		t.Fatal("expected signature verification error")
	}
}

func TestDiscoverRejectsIssuerMismatch(t *testing.T) {
	tp := newTestProvider(t)
	tp.claims = baseClaims(tp.issuer, tp.clientID, "nonce-abc")
	_, err := Discover(context.Background(), OIDCConfig{
		Issuer: tp.issuer + "/wrong", ClientID: tp.clientID, ClientSecret: "secret", RedirectURL: "https://proxy.example/callback",
	})
	if err == nil {
		t.Fatal("expected discovery issuer mismatch error")
	}
}
