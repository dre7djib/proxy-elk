package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"proxy/internal/auth"
)

const testSessionSecret = "01234567890123456789012345678901"

func TestKibanaSSOHandleLoginSuccessForwardsCookieAndRedirects(t *testing.T) {
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/security/login" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "kibana-session-opaque"})
		w.WriteHeader(http.StatusOK)
	}))
	defer kibana.Close()

	sessions := auth.NewSessions(auth.SessionConfig{Secret: []byte(testSessionSecret)})
	login := &KibanaSSOLogin{
		Directory: &fakeDirectory{authenticate: func(username, password string) (*auth.Identity, error) {
			return &auth.Identity{Subject: username}, nil
		}},
		KibanaURL: kibana.URL,
		PublicURL: "http://127.0.0.1:5601",
		Sessions:  sessions,
		Method:    auth.MethodLDAP,
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/kibana", strings.NewReader(url.Values{
		"username": {"alice"}, "password": {"alicepass"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	login.HandleLogin(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "http://127.0.0.1:5601" {
		t.Fatalf("Location = %q", loc)
	}
	var gotProxySession bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookieName {
			gotProxySession = true
		}
	}
	if !gotProxySession {
		t.Fatal("proxy session cookie not issued")
	}
	var gotKibanaCookie bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "sid" && c.Value == "kibana-session-opaque" {
			gotKibanaCookie = true
		}
	}
	if !gotKibanaCookie {
		t.Fatalf("kibana session cookie not forwarded: %v", rec.Header()["Set-Cookie"])
	}
}

func TestKibanaSSOHandleNegotiateNoTicketChallenges401(t *testing.T) {
	login := &KibanaSSOLogin{
		PublicURL: "http://127.0.0.1:5601",
		Kerberos:  auth.NewKerberosForTest("EXAMPLE.ORG"),
	}
	rec := httptest.NewRecorder()
	login.HandleNegotiate(rec, httptest.NewRequest(http.MethodGet, "/auth/kibana", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "Negotiate" {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

func TestKibanaSSOHandleNegotiateSuccessLogsInWithShadowAndRedirects(t *testing.T) {
	var gotParams map[string]string
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		params, _ := body["params"].(map[string]any)
		gotParams = map[string]string{}
		for k, v := range params {
			gotParams[k], _ = v.(string)
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "kibana-session-opaque"})
		w.WriteHeader(http.StatusOK)
	}))
	defer kibana.Close()

	k := auth.NewKerberosForTest("EXAMPLE.ORG")
	k.Accept = func(token string) (string, string, error) { return "alice", "EXAMPLE.ORG", nil }
	k.Lookup = func(ctx context.Context, username string) (*auth.Identity, error) {
		return &auth.Identity{Subject: username}, nil
	}

	sessions := auth.NewSessions(auth.SessionConfig{Secret: []byte(testSessionSecret)})
	login := &KibanaSSOLogin{
		KibanaURL:      kibana.URL,
		PublicURL:      "http://127.0.0.1:5601",
		Sessions:       sessions,
		Method:         auth.MethodKerberos,
		Kerberos:       k,
		ShadowPassword: "shadow-secret",
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/kibana", nil)
	req.Header.Set("Authorization", "Negotiate dG9rZW4=")
	rec := httptest.NewRecorder()
	login.HandleNegotiate(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "http://127.0.0.1:5601" {
		t.Fatalf("Location = %q", loc)
	}
	if gotParams["username"] != "alice" || gotParams["password"] != "shadow-secret" {
		t.Fatalf("kibana login params = %+v, want alice/shadow-secret", gotParams)
	}
	var gotProxySession bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookieName {
			gotProxySession = true
		}
	}
	if !gotProxySession {
		t.Fatal("proxy session cookie not issued")
	}
}

func TestKibanaSSOHandleLoginBadCredentialsNeverCallsKibana(t *testing.T) {
	var kibanaCalled bool
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kibanaCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer kibana.Close()

	login := &KibanaSSOLogin{
		Directory: &fakeDirectory{authenticate: func(username, password string) (*auth.Identity, error) {
			return nil, errAuthFailed
		}},
		KibanaURL: kibana.URL,
		PublicURL: "http://127.0.0.1:5601",
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/kibana", strings.NewReader(url.Values{
		"username": {"alice"}, "password": {"wrong"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	login.HandleLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if kibanaCalled {
		t.Fatal("kibana login must not be called on bad credentials")
	}
	if strings.Contains(rec.Body.String(), "wrong") {
		t.Fatalf("response leaked password: %s", rec.Body.String())
	}
}

func TestKibanaSSOHandleLoginKibanaRejectionIsBadGateway(t *testing.T) {
	kibana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer kibana.Close()

	login := &KibanaSSOLogin{
		Directory: &fakeDirectory{authenticate: func(username, password string) (*auth.Identity, error) {
			return &auth.Identity{Subject: username}, nil
		}},
		KibanaURL: kibana.URL,
		PublicURL: "http://127.0.0.1:5601",
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/kibana", strings.NewReader(url.Values{
		"username": {"alice"}, "password": {"alicepass"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	login.HandleLogin(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d", rec.Code)
	}
}
