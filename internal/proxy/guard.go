package proxy

import (
	"bytes"
	"context"
	"net/http"
	"strings"

	"proxy/internal/auth"
	"proxy/internal/limits"
)

// Guard enforces per-role limits (F25) around next: requests per minute,
// max duration, max response size. Identity comes from the session
// cookie or a Bearer JWT, the same lookup HandleMe uses. A request with
// no identity is not counted and passes straight through unguarded —
// that's also how /health, /metrics and /auth/* stay exempt, by simply
// never being wrapped in buildMux.
type Guard struct {
	Limits   *limits.Limits
	Counter  *limits.Counter
	Sessions *auth.Sessions
	JWT      *auth.JWT
}

// Wrap enforces the resolved quota around next. A nil *Guard is a no-op.
func (g *Guard) Wrap(next http.Handler) http.Handler {
	if g == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := g.identity(r)
		if id == nil {
			next.ServeHTTP(w, r)
			return
		}
		quota := g.Limits.Resolve(*id)
		if quota == nil {
			next.ServeHTTP(w, r)
			return
		}
		if !g.Counter.Allow(id.Subject, quota.RequestsPerMinute) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), quota.MaxDuration)
		defer cancel()

		buf := newBufferedResponse(quota.MaxResultBytes)
		done := make(chan struct{})
		go func() {
			next.ServeHTTP(buf, r.WithContext(ctx))
			close(done)
		}()

		select {
		case <-done:
			buf.flush(w)
		case <-ctx.Done():
			http.Error(w, "upstream deadline exceeded", http.StatusGatewayTimeout)
			// shortcut: the handler goroutine above keeps running against
			// buf, which nothing else reads after this point; fine at MVP
			// scale, revisit if a slow handler needs to be cancelled too.
		}
	})
}

func (g *Guard) identity(r *http.Request) *auth.Identity {
	if id, _, err := g.Sessions.FromRequest(r); err == nil {
		return id
	}
	if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && g.JWT != nil {
		if id, err := g.JWT.AuthenticateBearer(r.Context(), bearer); err == nil {
			return id
		}
	}
	return nil
}

// bufferedResponse holds a handler's response until it's known to be
// under the size limit: a response over the limit is thrown away whole,
// never truncated mid-JSON.
type bufferedResponse struct {
	header     http.Header
	statusCode int
	body       bytes.Buffer
	limit      int64
	over       bool
}

func newBufferedResponse(limit int64) *bufferedResponse {
	return &bufferedResponse{header: make(http.Header), statusCode: http.StatusOK, limit: limit}
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(code int) { b.statusCode = code }

func (b *bufferedResponse) Write(p []byte) (int, error) {
	if int64(b.body.Len()+len(p)) > b.limit {
		b.over = true
	}
	return b.body.Write(p)
}

// flush sends the buffered response to w, or a 413 with no body if it
// went over the limit.
func (b *bufferedResponse) flush(w http.ResponseWriter) {
	if b.over {
		http.Error(w, "response too large", http.StatusRequestEntityTooLarge)
		return
	}
	for k, v := range b.header {
		w.Header()[k] = v
	}
	w.WriteHeader(b.statusCode)
	w.Write(b.body.Bytes())
}
