package proxy

import (
	"context"
	"encoding/json"
	"net"
	"net/http"

	"proxy/internal/auth"
)

// LDAPDirectory is satisfied by *auth.LDAP; a narrow interface so tests can
// stub a directory without dialing one.
type LDAPDirectory interface {
	Authenticate(ctx context.Context, username, password string) (*auth.Identity, error)
}

// LDAPLogin authenticates POST /auth/ldap requests against a directory.
// OnSuccess is called with the verified Identity; it is responsible for
// starting the user's session, mirroring OIDCLogin.OnSuccess.
type LDAPLogin struct {
	Directory LDAPDirectory
	// Limiter blocks repeated failed logins for a (username, IP) pair
	// (F8). Nil disables lockout.
	Limiter   *auth.Limiter
	OnSuccess func(w http.ResponseWriter, r *http.Request, id auth.Identity)
}

type ldapLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// HandleLogin decodes {username,password}, authenticates against the
// directory, and never reports why a login failed: a wrong password, an
// unknown user and a lockout all get the same bare 401, so the response
// leaks nothing about the directory's contents or about the lockout state
// (F8).
func (l *LDAPLogin) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req ldapLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	ip := clientIP(r)
	if !l.Limiter.Allow(req.Username, ip) {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	id, err := l.Directory.Authenticate(r.Context(), req.Username, req.Password)
	if err != nil {
		l.Limiter.Fail(req.Username, ip)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	l.Limiter.Success(req.Username, ip)
	l.OnSuccess(w, r, *id)
}

// clientIP returns the request's source host, without its port. It never
// consults X-Forwarded-For: the proxy has no notion of a trusted upstream
// yet, and that header is trivially spoofable to dodge the lockout.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
