package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy/internal/auth"
	"proxy/internal/limits"
)

func testSessions(t *testing.T) *auth.Sessions {
	t.Helper()
	return auth.NewSessions(auth.SessionConfig{Secret: []byte("01234567890123456789012345678901")})
}

func withSessionCookie(t *testing.T, sessions *auth.Sessions, id auth.Identity) *http.Request {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := sessions.Issue(rec, id, auth.MethodLDAP); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	return r
}

func TestGuardNilIsNoOp(t *testing.T) {
	var g *Guard
	rec := httptest.NewRecorder()
	g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestGuardPassesThroughWithoutIdentity(t *testing.T) {
	l, err := limits.Parse(&limits.Role{MaxDuration: "30s", MaxResultBytes: 10, RequestsPerMinute: 1}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	g := &Guard{Limits: l, Counter: limits.NewCounter(), Sessions: testSessions(t)}
	rec := httptest.NewRecorder()
	g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, anonymous caller must not be counted/limited", rec.Code)
	}
}

func TestGuardUnderQuotaPassesBodyIntact(t *testing.T) {
	l, err := limits.Parse(&limits.Role{MaxDuration: "30s", MaxResultBytes: 1024, RequestsPerMinute: 10}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := testSessions(t)
	g := &Guard{Limits: l, Counter: limits.NewCounter(), Sessions: sessions}
	rec := httptest.NewRecorder()
	r := withSessionCookie(t, sessions, auth.Identity{Subject: "bob"})

	g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	})).ServeHTTP(rec, r)

	if rec.Code != http.StatusOK || rec.Body.String() != "hello" {
		t.Fatalf("status = %d, body = %q", rec.Code, rec.Body.String())
	}
}

func TestGuardRateLimit429(t *testing.T) {
	l, err := limits.Parse(&limits.Role{MaxDuration: "30s", MaxResultBytes: 1024, RequestsPerMinute: 1}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := testSessions(t)
	g := &Guard{Limits: l, Counter: limits.NewCounter(), Sessions: sessions}
	handler := g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, withSessionCookie(t, sessions, auth.Identity{Subject: "bob"}))
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request status = %d", rec1.Code)
	}

	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, withSessionCookie(t, sessions, auth.Identity{Subject: "bob"}))
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429", rec2.Code)
	}
}

func TestGuardSlowHandler504(t *testing.T) {
	l, err := limits.Parse(&limits.Role{MaxDuration: "10ms", MaxResultBytes: 1024, RequestsPerMinute: 10}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := testSessions(t)
	g := &Guard{Limits: l, Counter: limits.NewCounter(), Sessions: sessions}
	rec := httptest.NewRecorder()

	g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, withSessionCookie(t, sessions, auth.Identity{Subject: "bob"}))

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", rec.Code)
	}
}

func TestGuardOversizedBody413(t *testing.T) {
	l, err := limits.Parse(&limits.Role{MaxDuration: "30s", MaxResultBytes: 4, RequestsPerMinute: 10}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sessions := testSessions(t)
	g := &Guard{Limits: l, Counter: limits.NewCounter(), Sessions: sessions}
	rec := httptest.NewRecorder()

	g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"too":"big"}`))
	})).ServeHTTP(rec, withSessionCookie(t, sessions, auth.Identity{Subject: "bob"}))

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "big") {
		t.Fatalf("oversized body leaked through: %q", rec.Body.String())
	}
}
