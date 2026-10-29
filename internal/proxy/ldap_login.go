package proxy

import (
	"context"
	"encoding/json"
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
	OnSuccess func(w http.ResponseWriter, r *http.Request, id auth.Identity)
}

type ldapLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// HandleLogin decodes {username,password}, authenticates against the
// directory, and never reports why a login failed: a wrong password and an
// unknown user both get a bare 401, so the response leaks nothing about the
// directory's contents.
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

	id, err := l.Directory.Authenticate(r.Context(), req.Username, req.Password)
	if err != nil {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	l.OnSuccess(w, r, *id)
}
