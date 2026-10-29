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
	"net/url"
	"testing"
	"time"

	"proxy/internal/auth"
)

func newFakeProvider(t *testing.T) (setNonce func(string), issuer string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var expectedNonce string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/authorize",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "n": n, "e": e}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := map[string]any{
			"iss": issuer, "sub": "user-1", "email": "bob@example.com",
			"aud": "client-1", "nonce": expectedNonce, "exp": time.Now().Add(time.Hour).Unix(),
		}
		header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
		payload, _ := json.Marshal(claims)
		signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
		hash := sha256.Sum256([]byte(signingInput))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
		idToken := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
		json.NewEncoder(w).Encode(map[string]string{"access_token": "at", "id_token": idToken})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL
	return func(n string) { expectedNonce = n }, issuer
}

func TestOIDCLoginAndCallback(t *testing.T) {
	setNonce, issuer := newFakeProvider(t)
	provider, err := auth.Discover(context.Background(), auth.OIDCConfig{
		Issuer: issuer, ClientID: "client-1", ClientSecret: "s3cret", RedirectURL: "https://proxy.example/callback",
	})
	if err != nil {
		t.Fatal(err)
	}

	var gotIdentity auth.Identity
	login := &OIDCLogin{
		Provider: provider,
		OnSuccess: func(w http.ResponseWriter, r *http.Request, id auth.Identity) {
			gotIdentity = id
			w.WriteHeader(http.StatusOK)
		},
	}

	loginReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	loginRec := httptest.NewRecorder()
	login.HandleLogin(loginRec, loginReq)

	if loginRec.Code != http.StatusFound {
		t.Fatalf("login status = %d", loginRec.Code)
	}
	redirectURL, err := url.Parse(loginRec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := redirectURL.Query().Get("state")
	nonce := redirectURL.Query().Get("nonce")
	if state == "" || nonce == "" {
		t.Fatalf("redirect missing state/nonce: %s", redirectURL)
	}
	var stateCookieVal *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == stateCookie {
			stateCookieVal = c
		}
	}
	if stateCookieVal == nil {
		t.Fatal("no state cookie set")
	}
	setNonce(nonce)

	callbackURL := "/callback?state=" + url.QueryEscape(state) + "&code=any-code"
	callbackReq := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	callbackReq.AddCookie(stateCookieVal)
	callbackRec := httptest.NewRecorder()
	login.HandleCallback(callbackRec, callbackReq)

	if callbackRec.Code != http.StatusOK {
		t.Fatalf("callback status = %d body=%s", callbackRec.Code, callbackRec.Body.String())
	}
	if gotIdentity.Subject != "user-1" || gotIdentity.Email != "bob@example.com" {
		t.Fatalf("identity = %+v", gotIdentity)
	}
}

func TestOIDCCallbackRejectsStateMismatch(t *testing.T) {
	_, issuer := newFakeProvider(t)
	provider, err := auth.Discover(context.Background(), auth.OIDCConfig{
		Issuer: issuer, ClientID: "client-1", ClientSecret: "s3cret", RedirectURL: "https://proxy.example/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	login := &OIDCLogin{Provider: provider, OnSuccess: func(w http.ResponseWriter, r *http.Request, id auth.Identity) {
		t.Fatal("OnSuccess must not be called")
	}}

	req := httptest.NewRequest(http.MethodGet, "/callback?state=forged&code=any-code", nil)
	req.AddCookie(&http.Cookie{Name: stateCookie, Value: "real-state.real-nonce"})
	rec := httptest.NewRecorder()
	login.HandleCallback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestOIDCCallbackRequiresStateCookie(t *testing.T) {
	_, issuer := newFakeProvider(t)
	provider, err := auth.Discover(context.Background(), auth.OIDCConfig{
		Issuer: issuer, ClientID: "client-1", ClientSecret: "s3cret", RedirectURL: "https://proxy.example/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	login := &OIDCLogin{Provider: provider, OnSuccess: func(w http.ResponseWriter, r *http.Request, id auth.Identity) {
		t.Fatal("OnSuccess must not be called")
	}}

	req := httptest.NewRequest(http.MethodGet, "/callback?state=s&code=c", nil)
	rec := httptest.NewRecorder()
	login.HandleCallback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}
