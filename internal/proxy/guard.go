package proxy

import (
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
		limits.Enforce(g.Limits, g.Counter, g.identity(r), next).ServeHTTP(w, r)
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
