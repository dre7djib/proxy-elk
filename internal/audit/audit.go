// Package audit writes one JSON line per access request to stdout (F49):
// source, user and the allow/deny decision. Health and metrics scrapes
// never produce a line, and nothing from the request body, cookies or
// Authorization header is ever logged.
package audit

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"proxy/internal/auth"
)

// Source identifies which caller path produced the record. The HTTP
// middleware in this package always writes SourceUI; SourceMCP exists for
// the MCP server (J3) to use the same Logger once it calls Write itself.
// There is no client-supplied header for this — it would be forgeable.
type Source string

const (
	SourceUI  Source = "ui"
	SourceMCP Source = "mcp"
)

// Decision is whether the request was allowed or denied.
type Decision string

const (
	DecisionAllowed Decision = "allowed"
	DecisionDenied  Decision = "denied"
)

// Record is one audit line. User and Method are empty when the request
// carried no identity; Reason is set only when Decision is denied.
type Record struct {
	TS         string      `json:"ts"`
	Source     Source      `json:"source"`
	User       string      `json:"user,omitempty"`
	Method     auth.Method `json:"method,omitempty"`
	Decision   Decision    `json:"decision"`
	Reason     string      `json:"reason,omitempty"`
	HTTPMethod string      `json:"http_method"`
	Path       string      `json:"path"`
	Status     int         `json:"status"`
	DurationMS int64       `json:"duration_ms"`
	Bytes      int         `json:"bytes"`
}

// Logger writes Records as single JSON lines, serialized by the
// underlying *log.Logger.
type Logger struct {
	out  *log.Logger
	mask func(string) string
}

// New returns a Logger writing to w. mask is applied to Path and Reason
// before writing (config.Mask, to catch a secret that ended up there); a
// nil mask is a no-op.
func New(w io.Writer, mask func(string) string) *Logger {
	if mask == nil {
		mask = func(s string) string { return s }
	}
	return &Logger{out: log.New(w, "", 0), mask: mask}
}

// Write emits rec as one JSON line. A marshal failure (not expected for
// this struct) drops the line rather than panicking.
func (l *Logger) Write(rec Record) {
	rec.Path = l.mask(rec.Path)
	rec.Reason = l.mask(rec.Reason)
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	l.out.Print(string(b))
}

// Handler wraps next, writing one Record per request after it completes.
// /health, /healthz and /metrics are passed straight through with no
// line — a Prometheus scrape would drown out access decisions. Identity
// is resolved the same way Guard.identity does: session cookie first,
// then Bearer JWT.
func (l *Logger) Handler(sessions *auth.Sessions, jwt *auth.JWT, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health", "/healthz", "/metrics":
			next.ServeHTTP(w, r)
			return
		}

		user, method := identity(r, sessions, jwt)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r)
		duration := time.Since(start)

		out := Record{
			TS:         start.UTC().Format(time.RFC3339),
			Source:     SourceUI,
			User:       user,
			Method:     method,
			HTTPMethod: r.Method,
			Path:       r.URL.Path,
			Status:     rec.status,
			DurationMS: duration.Milliseconds(),
			Bytes:      rec.bytes,
		}
		if rec.status < 400 {
			out.Decision = DecisionAllowed
		} else {
			out.Decision = DecisionDenied
			out.Reason = reasonFor(rec.status)
		}
		l.Write(out)
	})
}

func identity(r *http.Request, sessions *auth.Sessions, jwt *auth.JWT) (user string, method auth.Method) {
	if id, m, err := sessions.FromRequest(r); err == nil {
		return id.Subject, m
	}
	if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && jwt != nil {
		if id, err := jwt.AuthenticateBearer(r.Context(), bearer); err == nil {
			return id.Subject, auth.MethodJWT
		}
	}
	return "", ""
}

func reasonFor(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "access denied"
	case http.StatusRequestEntityTooLarge:
		return "response too large"
	case http.StatusTooManyRequests:
		return "rate limit exceeded"
	case http.StatusGatewayTimeout:
		return "upstream deadline exceeded"
	default:
		return http.StatusText(status)
	}
}

// statusRecorder captures the status code and byte count actually sent
// to the client — on a 413 that's the guard's own error body, never the
// discarded upstream body.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	n, err := r.ResponseWriter.Write(p)
	r.bytes += n
	return n, err
}
