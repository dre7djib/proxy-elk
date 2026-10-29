package proxy

import (
	"encoding/json"
	"net/http"
	"strings"

	"proxy/internal/auth"
)

// meResponse is what GET /auth/me returns: the caller's own Identity, never
// anything from the login that produced it.
type meResponse struct {
	Subject string   `json:"subject"`
	Email   string   `json:"email"`
	Groups  []string `json:"groups"`
	Method  string   `json:"method"`
}

// HandleMe returns a handler reporting the caller's identity, from either
// the session cookie (human logins) or a Bearer JWT (M2M, F13). A missing,
// tampered or expired session (or sessions being nil, i.e. disabled), with
// no valid Bearer either, gets a bare 401.
func HandleMe(sessions *auth.Sessions, jwt *auth.JWT) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if id, method, err := sessions.FromRequest(r); err == nil {
			writeMe(w, id, method)
			return
		}
		if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && jwt != nil {
			if id, err := jwt.AuthenticateBearer(r.Context(), bearer); err == nil {
				writeMe(w, id, auth.MethodJWT)
				return
			}
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
}

func writeMe(w http.ResponseWriter, id *auth.Identity, method auth.Method) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(meResponse{
		Subject: id.Subject,
		Email:   id.Email,
		Groups:  id.Groups,
		Method:  string(method),
	})
}
