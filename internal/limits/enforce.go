package limits

import (
	"bytes"
	"context"
	"net/http"

	"proxy/internal/auth"
)

// Enforce wraps next with id's resolved quota (requests per minute, max
// duration, max response size): the same logic used by the login mux's
// Guard (identity from a session cookie or Bearer JWT) and by the
// Elasticsearch relay (identity resolved via LDAP Basic auth, run_as, or
// session/JWT, before either of them ever reaches a *Limits). A nil l or
// id, or an id with no matching quota, passes next through unguarded.
func Enforce(l *Limits, counter *Counter, id *auth.Identity, next http.Handler) http.Handler {
	if l == nil || id == nil {
		return next
	}
	quota := l.Resolve(*id)
	if quota == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !counter.Allow(id.Subject, quota.RequestsPerMinute) {
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
