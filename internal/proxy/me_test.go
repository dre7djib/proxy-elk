package proxy

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

	"proxy/internal/auth"
)

// newTestJWT runs a throwaway JWKS endpoint and returns a JWT verifier plus
// a signer for Bearer tokens it accepts, for exercising HandleMe's Bearer
// path without a real IdP.
func newTestJWT(t *testing.T) (*auth.JWT, func(claims map[string]any) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "test-key"
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		eBytes := big3(key.PublicKey.E)
		e := base64.RawURLEncoding.EncodeToString(eBytes)
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{"kty": "RSA", "kid": kid, "n": n, "e": e}},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	j, err := auth.NewJWT(context.Background(), auth.JWTConfig{
		Issuer: "https://idp.example", Audience: "proxy-m2m", JWKSURL: srv.URL + "/jwks",
	})
	if err != nil {
		t.Fatal(err)
	}

	sign := func(claims map[string]any) string {
		header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
		payload, _ := json.Marshal(claims)
		signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
		hash := sha256.Sum256([]byte(signingInput))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
		if err != nil {
			t.Fatal(err)
		}
		return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	return j, sign
}

func big3(e int) []byte {
	b := []byte{byte(e >> 16), byte(e >> 8), byte(e)}
	i := 0
	for i < len(b)-1 && b[i] == 0 {
		i++
	}
	return b[i:]
}

func TestHandleMeWithValidSession(t *testing.T) {
	sessions := auth.NewSessions(auth.SessionConfig{Secret: []byte("0123456789abcdef0123456789abcdef")})
	issueRec := httptest.NewRecorder()
	if err := sessions.Issue(issueRec, auth.Identity{Subject: "alice", Email: "alice@example.com", Groups: []string{"g1"}}, auth.MethodLDAP); err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	for _, c := range issueRec.Result().Cookies() {
		if c.Name == auth.SessionCookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie")
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	HandleMe(sessions, nil)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var got meResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Subject != "alice" || got.Method != string(auth.MethodLDAP) || len(got.Groups) != 1 {
		t.Fatalf("response = %+v", got)
	}
}

func TestHandleMeWithoutCookie(t *testing.T) {
	sessions := auth.NewSessions(auth.SessionConfig{Secret: []byte("0123456789abcdef0123456789abcdef")})
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	rec := httptest.NewRecorder()
	HandleMe(sessions, nil)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestHandleMeNilSessionsAlwaysUnauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	rec := httptest.NewRecorder()
	HandleMe(nil, nil)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestHandleMeWithValidBearer(t *testing.T) {
	jwt, sign := newTestJWT(t)
	token := sign(map[string]any{
		"iss": "https://idp.example", "sub": "service-1", "aud": "proxy-m2m",
		"exp": time.Now().Add(time.Hour).Unix(), "groups": []string{"m2m-readers"},
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	HandleMe(nil, jwt)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var got meResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Subject != "service-1" || got.Method != string(auth.MethodJWT) {
		t.Fatalf("response = %+v", got)
	}
}

func TestHandleMeWithExpiredBearer(t *testing.T) {
	jwt, sign := newTestJWT(t)
	token := sign(map[string]any{
		"iss": "https://idp.example", "sub": "service-1", "aud": "proxy-m2m",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	HandleMe(nil, jwt)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestHandleMeWithMissingBearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	rec := httptest.NewRecorder()
	HandleMe(nil, nil)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}
