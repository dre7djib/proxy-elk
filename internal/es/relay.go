package es

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"proxy/internal/acl"
	"proxy/internal/auth"
	"proxy/internal/limits"
)

var errLDAPDisabled = errors.New("es: ldap authentication is disabled")

// Config wires a Relay. Policy is called once per request, not captured
// at construction time, so a live ACL reload (SIGHUP, F23) is picked up
// without rebuilding the relay.
type Config struct {
	Target *url.URL

	// LDAP authenticates Basic auth that isn't one of Passthrough (nil
	// disables that path: every Basic request other than Passthrough gets
	// a 401). Sessions and JWT back the cookie/Bearer fallback, same
	// lookup as /auth/me.
	LDAP     auth.PasswordAuthenticator
	Sessions *auth.Sessions
	JWT      *auth.JWT
	// Kerberos authenticates an Authorization: Negotiate request (SPNEGO),
	// resolving groups via LDAP (Kerberos itself carries no password).
	// Nil disables that path: a Negotiate header gets no special
	// treatment and falls through to the 401 below.
	Kerberos *auth.Kerberos

	// Limits/Counter enforce the resolved identity's quota (F25), via
	// limits.Enforce — the same logic the login mux's Guard uses for
	// session/JWT identities, applied here for identities Guard never
	// sees (LDAP Basic auth). Either may be nil for no quota at all.
	Limits  *limits.Limits
	Counter *limits.Counter

	Policy   func() *acl.Policy
	Resolver acl.IndexResolver

	// RunAsUser/RunAsPassword authenticate upstream once ACL allows a
	// request; es-security-runas-user then impersonates the caller (F2).
	RunAsUser     string
	RunAsPassword string
	// ShadowPassword is substituted into POST
	// /_security/profile/_activate for an LDAP user (see activate.go).
	// Basic auth carrying it directly (rather than a real LDAP password)
	// resolves via Lookup instead of a bind: Kerberos's /auth/kibana SSO
	// has no LDAP password, so it logs into Kibana with ShadowPassword,
	// and Kibana's own basic provider then re-validates those exact
	// credentials against the relay via GET /_security/_authenticate —
	// confirmed by running the demo end-to-end, where that call
	// otherwise hits the LDAP bind below and fails.
	ShadowPassword string
	// Lookup resolves a username with no password check, normally
	// *auth.LDAP.Lookup. Used only for the ShadowPassword case above.
	Lookup func(ctx context.Context, username string) (*auth.Identity, error)
	// Passthrough relays unchanged, with its own Basic credentials, never
	// through the ACL (kibana_system).
	Passthrough map[string]bool

	// BindCacheTTL caches a successful LDAP bind this long. Defaults to 1m.
	BindCacheTTL time.Duration
}

// NewRelay returns the catch-all handler proxying to cfg.Target.
func NewRelay(cfg Config) http.Handler {
	if cfg.BindCacheTTL <= 0 {
		cfg.BindCacheTTL = time.Minute
	}
	rp := httputil.NewSingleHostReverseProxy(cfg.Target)
	rl := &relay{cfg: cfg, proxy: rp, cache: newBindCache()}
	return http.HandlerFunc(rl.serveHTTP)
}

type relay struct {
	cfg   Config
	proxy *httputil.ReverseProxy
	cache *bindCache
}

func (rl *relay) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Basic ") {
		user, password, ok := decodeBasicAuth(authHeader)
		if !ok {
			http.Error(w, "invalid Basic Authorization", http.StatusUnauthorized)
			return
		}
		if rl.cfg.Passthrough[user] {
			if r.Method == http.MethodPost && r.URL.Path == "/_security/profile/_activate" {
				rl.activate(w, r)
				return
			}
			rl.proxy.ServeHTTP(w, r)
			return
		}
		if rl.cfg.Lookup != nil && rl.cfg.ShadowPassword != "" &&
			subtle.ConstantTimeCompare([]byte(password), []byte(rl.cfg.ShadowPassword)) == 1 {
			id, err := rl.cfg.Lookup(r.Context(), user)
			if err != nil {
				http.Error(w, "LDAP authentication denied", http.StatusUnauthorized)
				return
			}
			rl.guarded(id, w, r)
			return
		}

		id, err := rl.ldapBind(r, user, password)
		if err != nil {
			http.Error(w, "LDAP authentication denied", http.StatusUnauthorized)
			return
		}
		rl.guarded(id, w, r)
		return
	}

	if strings.HasPrefix(r.Header.Get("Authorization"), "Negotiate ") && rl.cfg.Kerberos != nil {
		if id, err := rl.cfg.Kerberos.Authenticate(r); err == nil {
			rl.guarded(id, w, r)
			return
		}
	}

	if id, _, err := rl.cfg.Sessions.FromRequest(r); err == nil {
		rl.guarded(id, w, r)
		return
	}
	if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && rl.cfg.JWT != nil {
		if id, err := rl.cfg.JWT.AuthenticateBearer(r.Context(), bearer); err == nil {
			rl.guarded(id, w, r)
			return
		}
	}
	if rl.cfg.Kerberos != nil {
		w.Header().Set("WWW-Authenticate", "Negotiate")
	}
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

// guarded applies the resolved identity's quota, then Decide, then the
// relay. Not a second Guard.Wrap: id is already known here (LDAP Basic,
// session or JWT), so this calls limits.Enforce directly instead of
// re-resolving identity through the login mux's cookie/Bearer-only logic.
func (rl *relay) guarded(id *auth.Identity, w http.ResponseWriter, r *http.Request) {
	limits.Enforce(rl.cfg.Limits, rl.cfg.Counter, id, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rl.decideAndForward(w, r, *id)
	})).ServeHTTP(w, r)
}

// selfAuthenticatePath is exempt from the ACL cluster_admin block: it is
// how ES tells an already-authenticated caller its own identity, not a
// data access or administrative action (any ES user can call it on
// themselves). Kibana's basic-auth login calls this to validate the
// password it was handed, so blocking it breaks every login (J1-15).
const selfAuthenticatePath = "/_security/_authenticate"

// selfPrivilegesPath is exempt for the same reason: without a username
// segment ES answers only for the (run_as) caller itself. Kibana's spaces
// plugin calls it on every page load, so blocking it 500s the UI.
const selfPrivilegesPath = "/_security/user/_has_privileges"

func (rl *relay) decideAndForward(w http.ResponseWriter, r *http.Request, id auth.Identity) {
	if r.URL.Path == selfAuthenticatePath && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		r.Header.Set("Authorization", basicAuthHeader(rl.cfg.RunAsUser, rl.cfg.RunAsPassword))
		r.Header.Set("es-security-runas-user", id.Subject)
		rl.proxy.ServeHTTP(w, r)
		return
	}

	if r.URL.Path == selfPrivilegesPath && (r.Method == http.MethodGet || r.Method == http.MethodPost) {
		r.Header.Set("Authorization", basicAuthHeader(rl.cfg.RunAsUser, rl.cfg.RunAsPassword))
		r.Header.Set("es-security-runas-user", id.Subject)
		rl.proxy.ServeHTTP(w, r)
		return
	}

	action := acl.Classify(r.Method, r.URL.Path)
	names := indicesFromPath(r.URL.Path)

	var resolved []string
	if len(names) > 0 {
		var err error
		resolved, err = rl.cfg.Resolver.Resolve(r.Context(), names)
		if err != nil {
			http.Error(w, "index resolution failed", http.StatusBadGateway)
			return
		}
	}

	decideCtx := acl.DecideContext{RemoteAddr: r.RemoteAddr, Method: r.Method, Time: time.Now()}
	if err := rl.cfg.Policy().Decide(id, decideCtx, resolved, action); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	r.Header.Set("Authorization", basicAuthHeader(rl.cfg.RunAsUser, rl.cfg.RunAsPassword))
	r.Header.Set("es-security-runas-user", id.Subject)
	rl.proxy.ServeHTTP(w, r)
}

// ldapBind authenticates (user, password) against LDAP, reusing a recent
// successful bind from cache instead of re-dialing the directory.
func (rl *relay) ldapBind(r *http.Request, user, password string) (*auth.Identity, error) {
	if rl.cfg.LDAP == nil {
		return nil, errLDAPDisabled
	}
	if id, ok := rl.cache.get(user, password); ok {
		return id, nil
	}
	id, err := rl.cfg.LDAP.Authenticate(r.Context(), user, password)
	if err != nil {
		return nil, err
	}
	rl.cache.put(user, password, id, rl.cfg.BindCacheTTL)
	return id, nil
}

func decodeBasicAuth(header string) (user, password string, ok bool) {
	encoded := strings.TrimPrefix(header, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}
	user, password, ok = strings.Cut(string(decoded), ":")
	return user, password, ok
}

func basicAuthHeader(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}
