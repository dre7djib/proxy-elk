package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"proxy/internal/auth"
)

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
	HandleMe(sessions)(rec, req)

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
	HandleMe(sessions)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestHandleMeNilSessionsAlwaysUnauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	rec := httptest.NewRecorder()
	HandleMe(nil)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}
