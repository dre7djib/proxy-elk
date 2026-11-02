package proxy

import (
	"net/http"
	"time"

	"proxy/internal/auth"
)

// stateCookie carries state and nonce between /login and /callback without
// server-side storage. It never holds a password or token.
const stateCookie = "oidc_state"

// OIDCLogin drives the authorization code flow against provider. OnSuccess
// is called with the verified Identity once /callback completes; it is
// responsible for starting the user's session. Secure matches the session
// cookie: set only when the redirect URL is https, so an HTTP demo can
// send oidc_state back on the callback.
type OIDCLogin struct {
	Provider  *auth.Provider
	OnSuccess func(w http.ResponseWriter, r *http.Request, id auth.Identity)
	Secure    bool
}

// HandleLogin redirects the browser to the provider's authorization endpoint.
func (o *OIDCLogin) HandleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := auth.NewState()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := auth.NewState()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, o.stateCookie(state+"."+nonce, time.Now().Add(5*time.Minute)))
	http.Redirect(w, r, o.Provider.AuthCodeURL(state, nonce), http.StatusFound)
}

// HandleCallback validates the provider's response and exchanges the
// authorization code for an ID token.
func (o *OIDCLogin) HandleCallback(w http.ResponseWriter, r *http.Request) {
	cleared := o.stateCookie("", time.Unix(0, 0))
	cleared.MaxAge = -1
	http.SetCookie(w, cleared)

	cookie, err := r.Cookie(stateCookie)
	if err != nil || cookie.Value == "" {
		http.Error(w, "missing state", http.StatusBadRequest)
		return
	}
	state, nonce, ok := splitOnce(cookie.Value, '.')
	if !ok {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != state {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	id, err := o.Provider.Exchange(r.Context(), code, nonce)
	if err != nil {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	o.OnSuccess(w, r, id)
}

func (o *OIDCLogin) stateCookie(value string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     stateCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   o.Secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	}
}

func splitOnce(s string, sep byte) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}
