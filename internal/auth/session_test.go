package auth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestSessions() *Sessions {
	return NewSessions(SessionConfig{Secret: []byte("0123456789abcdef0123456789abcdef"), TTL: time.Hour})
}

func issue(t *testing.T, s *Sessions, id Identity, method Method) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := s.Issue(rec, id, method); err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	for _, c := range cookies {
		if c.Name == SessionCookieName {
			return c
		}
	}
	t.Fatal("no session cookie issued")
	return nil
}

func TestSessionIssueAndFromRequest(t *testing.T) {
	s := newTestSessions()
	id := Identity{Subject: "alice", Email: "alice@example.com", Groups: []string{"team-viewer"}}
	cookie := issue(t, s, id, MethodLDAP)

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(cookie)

	got, method, err := s.FromRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != id.Subject || got.Email != id.Email || len(got.Groups) != 1 || got.Groups[0] != "team-viewer" {
		t.Fatalf("identity = %+v", got)
	}
	if method != MethodLDAP {
		t.Fatalf("method = %q", method)
	}
}

func TestSessionFromRequestNoCookie(t *testing.T) {
	s := newTestSessions()
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	if _, _, err := s.FromRequest(req); err == nil {
		t.Fatal("expected error without a cookie")
	}
}

func TestSessionFromRequestRejectsTamperedPayload(t *testing.T) {
	s := newTestSessions()
	cookie := issue(t, s, Identity{Subject: "alice"}, MethodOIDC)

	encoded, sig, _ := strings.Cut(cookie.Value, ".")
	tampered := encoded + "x" + "." + sig
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tampered})

	if _, _, err := s.FromRequest(req); err == nil {
		t.Fatal("expected signature verification to fail")
	}
}

func TestSessionFromRequestRejectsWrongSecret(t *testing.T) {
	issuer := newTestSessions()
	cookie := issue(t, issuer, Identity{Subject: "alice"}, MethodOIDC)

	other := NewSessions(SessionConfig{Secret: []byte("fedcba9876543210fedcba9876543210")})
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(cookie)
	if _, _, err := other.FromRequest(req); err == nil {
		t.Fatal("expected a different secret to reject the cookie")
	}
}

func TestSessionFromRequestRejectsExpired(t *testing.T) {
	s := newTestSessions()
	// TTL <= 0 falls back to the 8h default (Issue has no "expired on
	// purpose" mode), so an already-expired cookie is built by hand here.
	claims := sessionClaims{Subject: "alice", Exp: time.Now().Add(-time.Hour).Unix()}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	value := encoded + "." + s.sign(encoded)

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: value})
	if _, _, err := s.FromRequest(req); err == nil {
		t.Fatal("expected expired session to be rejected")
	}
}

func TestSessionCookieNeverCarriesPassword(t *testing.T) {
	s := newTestSessions()
	cookie := issue(t, s, Identity{Subject: "alice", Email: "alice@example.com"}, MethodLDAP)
	if strings.Contains(cookie.Value, "s3cr3t-password") {
		t.Fatal("cookie leaked a value it should never have been given")
	}
}

func TestSessionClearExpiresCookie(t *testing.T) {
	s := newTestSessions()
	rec := httptest.NewRecorder()
	s.Clear(rec)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != SessionCookieName || !cookies[0].Expires.Before(time.Now()) {
		t.Fatalf("cookies = %+v", cookies)
	}
}

func TestNilSessionsNeverPanics(t *testing.T) {
	var s *Sessions
	if err := s.Issue(httptest.NewRecorder(), Identity{}, MethodOIDC); err == nil {
		t.Fatal("expected nil Sessions to refuse Issue")
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	if _, _, err := s.FromRequest(req); err == nil {
		t.Fatal("expected nil Sessions to refuse FromRequest")
	}
	s.Clear(httptest.NewRecorder()) // must not panic
}
