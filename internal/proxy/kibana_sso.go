package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"

	"proxy/internal/auth"
)

// KibanaSSOLogin serves a minimal login form and, on success, logs the
// browser into Kibana's own session on the user's behalf (server-side
// POST /internal/security/login) before redirecting it there, so
// Kibana's own login screen never appears. The proxy already re-verifies
// an LDAP user's password for the ES relay's run_as/_activate flow
// (internal/es); reusing it once more for Kibana's login needs no extra
// credential store and never persists the plaintext password.
type KibanaSSOLogin struct {
	Directory LDAPDirectory
	// Limiter blocks repeated failed logins for a (username, IP) pair
	// (F8), same as LDAPLogin. Nil disables lockout.
	Limiter *auth.Limiter

	// KibanaURL is the address the proxy itself calls (container-internal,
	// e.g. http://kibana:5601). PublicURL is where the browser is
	// redirected afterwards (e.g. http://127.0.0.1:5601) — the two differ
	// whenever Kibana isn't reachable from the browser under the name the
	// proxy uses internally, true of every docker-compose demo.
	KibanaURL string
	PublicURL string

	// Sessions, if set, additionally starts the proxy's own session (same
	// cookie as /auth/ldap) under Method, so /auth/me also reflects the
	// SSO login. Issued directly here, then a single redirect to
	// PublicURL: unlike OIDCLogin/LDAPLogin's OnSuccess (which redirects
	// to /auth/me), a second http.Redirect after one that already wrote
	// the response wouldn't replace it, so this never goes through that
	// shared helper.
	Sessions *auth.Sessions
	Method   auth.Method

	// Kerberos, if set, makes GET /auth/kibana the SPNEGO/Negotiate
	// challenge instead of the login form: no username/password field is
	// ever rendered. ShadowPassword is what's logged into Kibana on the
	// caller's behalf, since Kerberos carries no password at all — the
	// same native-realm secret internal/es substitutes into
	// POST /_security/profile/_activate.
	Kerberos       *auth.Kerberos
	ShadowPassword string

	// Client issues the server-side call to Kibana. Defaults to
	// http.DefaultClient.
	Client *http.Client
}

// HandleForm renders the login page (GET): username/password, nothing
// else — no Kibana branding, since this login never reaches Kibana's own
// page.
func (k *KibanaSSOLogin) HandleForm(w http.ResponseWriter, r *http.Request) {
	k.renderForm(w, "")
}

// HandleLogin authenticates the posted form against the directory, logs
// the browser into Kibana on its behalf, and redirects it there. Like
// LDAPLogin, it never reports why a login failed.
func (k *KibanaSSOLogin) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	if username == "" {
		k.renderForm(w, "identifiants invalides")
		return
	}

	ip := clientIP(r)
	if !k.Limiter.Allow(username, ip) {
		k.renderForm(w, "identifiants invalides")
		return
	}

	id, err := k.Directory.Authenticate(r.Context(), username, password)
	if err != nil {
		k.Limiter.Fail(username, ip)
		k.renderForm(w, "identifiants invalides")
		return
	}
	k.Limiter.Success(username, ip)

	if err := k.loginKibana(r, w, username, password); err != nil {
		log.Printf("kibana sso: login %q: %v", username, err)
		http.Error(w, "connexion à Kibana impossible", http.StatusBadGateway)
		return
	}

	k.finish(w, r, *id)
}

// HandleNegotiate serves GET /auth/kibana when Kerberos is active: the
// SPNEGO/Negotiate challenge/response replaces the login form entirely,
// with the login form only as fallback when no ticket is sent. A validated ticket logs the browser into
// Kibana with ShadowPassword — Kerberos never has the user's real
// password — and redirects it there.
func (k *KibanaSSOLogin) HandleNegotiate(w http.ResponseWriter, r *http.Request) {
	id, err := k.Kerberos.Authenticate(r)
	if err != nil {
		// No valid ticket: challenge Negotiate (a configured browser retries
		// with one) and show the login form as fallback for the others.
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
		k.renderForm(w, "")
		return
	}
	if err := k.loginKibana(r, w, id.Subject, k.ShadowPassword); err != nil {
		log.Printf("kibana sso: login %q: %v", id.Subject, err)
		http.Error(w, "connexion à Kibana impossible", http.StatusBadGateway)
		return
	}
	k.finish(w, r, *id)
}

// finish issues the proxy's own session cookie (if Sessions is set) and
// redirects to Kibana — the only place either SSO entry point (form
// login or Kerberos Negotiate) touches the response after a successful
// Kibana login.
func (k *KibanaSSOLogin) finish(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if k.Sessions != nil {
		if err := k.Sessions.Issue(w, id, k.Method); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, k.PublicURL, http.StatusFound)
}

// loginKibana calls Kibana's own basic-provider login server-side with
// the password just verified against LDAP, and relays its session
// cookie(s) onto w. Cookies set with no Domain are host-only but
// port-agnostic (RFC 6265): the browser sends them to Kibana's port on
// the same host without any extra configuration.
func (k *KibanaSSOLogin) loginKibana(r *http.Request, w http.ResponseWriter, username, password string) error {
	body, err := json.Marshal(map[string]any{
		"providerType": "basic",
		"providerName": "basic",
		"currentURL":   "/",
		"params": map[string]string{
			"username": username,
			"password": password,
		},
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, k.KibanaURL+"/internal/security/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("kbn-xsrf", "true")
	req.Header.Set("Content-Type", "application/json")

	client := k.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kibana login: status %d", resp.StatusCode)
	}

	for _, c := range resp.Cookies() {
		c.Domain = ""
		http.SetCookie(w, c)
	}
	return nil
}

func (k *KibanaSSOLogin) renderForm(w http.ResponseWriter, errMsg string) {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<p style="color:#b00">` + html.EscapeString(errMsg) + `</p>`
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>Connexion</title></head>
<body style="font-family:sans-serif;max-width:20rem;margin:4rem auto">
<h1>Connexion</h1>
%s
<form method="post">
<p><input name="username" placeholder="utilisateur" autofocus style="width:100%%"></p>
<p><input name="password" type="password" placeholder="mot de passe" style="width:100%%"></p>
<button type="submit">Se connecter</button>
</form>
</body></html>`, errHTML)
}
