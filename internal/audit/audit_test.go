package audit

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proxy/internal/auth"
)

func testSessions(t *testing.T) *auth.Sessions {
	t.Helper()
	return auth.NewSessions(auth.SessionConfig{Secret: []byte("01234567890123456789012345678901")})
}

func withSessionCookie(t *testing.T, sessions *auth.Sessions, id auth.Identity, method auth.Method) *http.Request {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := sessions.Issue(rec, id, method); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	return r
}

func TestWriteOmitsReasonWhenAllowed(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, nil)
	l.Write(Record{Decision: DecisionAllowed, Status: 200})

	line := strings.TrimSpace(buf.String())
	if strings.Contains(line, `"reason"`) {
		t.Fatalf("allowed line must not have reason: %s", line)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("not valid JSON: %v", line)
	}
	for _, key := range []string{"ts", "source", "decision", "http_method", "path", "status", "duration_ms", "bytes"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("missing key %q in %v", key, m)
		}
	}
}

func TestWriteAcceptsMCPSource(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, nil)
	l.Write(Record{Source: SourceMCP, Decision: DecisionAllowed})

	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &m); err != nil {
		t.Fatal(err)
	}
	if m["source"] != "mcp" {
		t.Fatalf("source = %v", m["source"])
	}
}

func TestWriteIsOneLine(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, nil)
	l.Write(Record{Decision: DecisionAllowed})
	l.Write(Record{Decision: DecisionDenied, Reason: "access denied"})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), buf.String())
	}
}

func TestHandlerAllowedWithSessionFillsUserAndMethod(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, nil)
	sessions := testSessions(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	r := withSessionCookie(t, sessions, auth.Identity{Subject: "alice"}, auth.MethodLDAP)
	l.Handler(sessions, nil, next).ServeHTTP(httptest.NewRecorder(), r)

	var rec Record
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Decision != DecisionAllowed {
		t.Fatalf("decision = %q", rec.Decision)
	}
	if rec.User != "alice" || rec.Method != auth.MethodLDAP {
		t.Fatalf("user/method = %q/%q", rec.User, rec.Method)
	}
	if rec.Reason != "" {
		t.Fatalf("reason = %q, want empty", rec.Reason)
	}
	if rec.Bytes != 2 {
		t.Fatalf("bytes = %d, want 2", rec.Bytes)
	}
}

func TestHandlerDeniedCatchAll(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "access denied", http.StatusForbidden)
	})
	l.Handler(nil, nil, next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/anything", nil))

	var rec Record
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Decision != DecisionDenied || rec.Reason != "access denied" {
		t.Fatalf("decision/reason = %q/%q", rec.Decision, rec.Reason)
	}
	if rec.User != "" {
		t.Fatalf("user = %q, want empty for anonymous caller", rec.User)
	}
}

func TestHandlerDeniedAuthMeWithoutCookie(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	l.Handler(nil, nil, next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/me", nil))

	var rec Record
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Decision != DecisionDenied || rec.Reason != "unauthorized" {
		t.Fatalf("decision/reason = %q/%q", rec.Decision, rec.Reason)
	}
}

func TestHandlerSkipsHealthAndMetrics(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	for _, path := range []string{"/health", "/healthz", "/metrics"} {
		l.Handler(nil, nil, next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}
	if buf.Len() != 0 {
		t.Fatalf("expected no audit line for health/metrics, got: %s", buf.String())
	}
}

func TestHandlerDropsQueryString(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	l.Handler(nil, nil, next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/callback?code=super-secret-oidc-code", nil))

	line := buf.String()
	if strings.Contains(line, "super-secret-oidc-code") {
		t.Fatalf("query string leaked into audit line: %s", line)
	}
	var rec Record
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Path != "/auth/callback" {
		t.Fatalf("path = %q", rec.Path)
	}
}

func TestHandlerDoesNotLogRequestBody(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/ldap", strings.NewReader(`{"password":"super-secret-password"}`))
	l.Handler(nil, nil, next).ServeHTTP(httptest.NewRecorder(), req)

	if strings.Contains(buf.String(), "super-secret-password") {
		t.Fatalf("request body leaked into audit line: %s", buf.String())
	}
}

func TestWriteMasksPathAndReason(t *testing.T) {
	var buf bytes.Buffer
	mask := func(s string) string { return strings.ReplaceAll(s, "topsecret", "***") }
	l := New(&buf, mask)
	l.Write(Record{Decision: DecisionDenied, Path: "/x/topsecret", Reason: "topsecret failure"})

	if strings.Contains(buf.String(), "topsecret") {
		t.Fatalf("secret leaked through unmasked: %s", buf.String())
	}
}
