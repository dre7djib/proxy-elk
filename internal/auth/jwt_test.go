package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// testJWKS runs a fake IdP's JWKS endpoint, signing Bearer tokens with a
// freshly generated RSA key. Reuses the shape of testProvider (oidc_test.go)
// but only the JWKS side: a Bearer verifier never talks to a token endpoint.
type testJWKS struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string
}

func newTestJWKS(t *testing.T) *testJWKS {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tj := &testJWKS{key: key, kid: "test-key"}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(bigEndianBytes(key.PublicKey.E))
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": tj.kid, "n": n, "e": e,
			}},
		})
	})
	tj.srv = httptest.NewServer(mux)
	t.Cleanup(tj.srv.Close)
	return tj
}

func (tj *testJWKS) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": tj.kid, "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, tj.key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func bearerClaimsFor(issuer, audience string) map[string]any {
	return map[string]any{
		"iss":    issuer,
		"sub":    "service-account-1",
		"aud":    audience,
		"exp":    time.Now().Add(time.Hour).Unix(),
		"groups": []string{"m2m-readers"},
	}
}

func TestAuthenticateBearerValid(t *testing.T) {
	tj := newTestJWKS(t)
	j, err := NewJWT(context.Background(), JWTConfig{
		Issuer: "https://idp.example", Audience: "proxy-m2m", JWKSURL: tj.srv.URL + "/jwks",
	})
	if err != nil {
		t.Fatal(err)
	}
	token := tj.sign(t, bearerClaimsFor("https://idp.example", "proxy-m2m"))

	id, err := j.AuthenticateBearer(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "service-account-1" {
		t.Fatalf("subject = %q", id.Subject)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "m2m-readers" {
		t.Fatalf("groups = %v", id.Groups)
	}
}

func TestAuthenticateBearerRejectsExpired(t *testing.T) {
	tj := newTestJWKS(t)
	j, err := NewJWT(context.Background(), JWTConfig{
		Issuer: "https://idp.example", Audience: "proxy-m2m", JWKSURL: tj.srv.URL + "/jwks",
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := bearerClaimsFor("https://idp.example", "proxy-m2m")
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	token := tj.sign(t, claims)

	if _, err := j.AuthenticateBearer(context.Background(), token); err == nil {
		t.Fatal("expected expired token error")
	}
}

func TestAuthenticateBearerRejectsWrongAudience(t *testing.T) {
	tj := newTestJWKS(t)
	j, err := NewJWT(context.Background(), JWTConfig{
		Issuer: "https://idp.example", Audience: "proxy-m2m", JWKSURL: tj.srv.URL + "/jwks",
	})
	if err != nil {
		t.Fatal(err)
	}
	token := tj.sign(t, bearerClaimsFor("https://idp.example", "someone-else"))

	if _, err := j.AuthenticateBearer(context.Background(), token); err == nil {
		t.Fatal("expected audience mismatch error")
	}
}

func TestAuthenticateBearerRejectsWrongIssuer(t *testing.T) {
	tj := newTestJWKS(t)
	j, err := NewJWT(context.Background(), JWTConfig{
		Issuer: "https://idp.example", Audience: "proxy-m2m", JWKSURL: tj.srv.URL + "/jwks",
	})
	if err != nil {
		t.Fatal(err)
	}
	token := tj.sign(t, bearerClaimsFor("https://attacker.example", "proxy-m2m"))

	if _, err := j.AuthenticateBearer(context.Background(), token); err == nil {
		t.Fatal("expected issuer mismatch error")
	}
}

func TestAuthenticateBearerRejectsBadSignature(t *testing.T) {
	tj := newTestJWKS(t)
	j, err := NewJWT(context.Background(), JWTConfig{
		Issuer: "https://idp.example", Audience: "proxy-m2m", JWKSURL: tj.srv.URL + "/jwks",
	})
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	original := tj.key
	tj.key = otherKey
	token := tj.sign(t, bearerClaimsFor("https://idp.example", "proxy-m2m"))
	tj.key = original

	if _, err := j.AuthenticateBearer(context.Background(), token); err == nil {
		t.Fatal("expected signature verification error")
	}
}

func TestAuthenticateBearerRejectsMalformed(t *testing.T) {
	tj := newTestJWKS(t)
	j, err := NewJWT(context.Background(), JWTConfig{
		Issuer: "https://idp.example", Audience: "proxy-m2m", JWKSURL: tj.srv.URL + "/jwks",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", "not-a-jwt", "a.b"} {
		if _, err := j.AuthenticateBearer(context.Background(), raw); err == nil {
			t.Fatalf("expected malformed error for %q", raw)
		}
	}
}
