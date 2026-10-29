package proxy

import (
	"encoding/json"
	"net/http"

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

// HandleMe returns a handler reporting the caller's session identity. A
// missing, tampered or expired session (or sessions being nil, i.e.
// disabled) gets a bare 401.
func HandleMe(sessions *auth.Sessions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, method, err := sessions.FromRequest(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meResponse{
			Subject: id.Subject,
			Email:   id.Email,
			Groups:  id.Groups,
			Method:  string(method),
		})
	}
}
