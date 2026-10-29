// Spike proxy for SP-02/SP-03: a reverse proxy between Kibana and
// Elasticsearch that logs every call as JSON on stdout (SP-02) and,
// from SP-03 onward, validates LDAP logins (search-then-bind) then talks to
// Elasticsearch with a service account while impersonating the
// user (`es-security-runas-user`, spike path A). Calls from
// service accounts (kibana_system, elastic, proxy_service) and anything
// that is not Basic auth (ApiKey, Bearer, no header) pass through
// unmodified. From SP-06, the proxy also answers itself (without relaying to
// Elasticsearch) on POST /_spike/identity-token: it issues a short-lived
// signed token (JWT RS256, F78) carrying the request's already-authenticated identity.
// Throwaway code: no tests, ACL/J1 out of scope.
package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/golang-jwt/jwt/v5"
)

// logEntry is one call-log line (one per request).
type logEntry struct {
	Timestamp   string `json:"ts"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Query       string `json:"query,omitempty"`
	Status      int    `json:"status"`
	DurationMS  int64  `json:"duration_ms"`
	Security    bool   `json:"security"`
	KibanaIndex bool   `json:"kibana_index"`
	AuthScheme  string `json:"auth_scheme,omitempty"`
	User        string `json:"user,omitempty"`
	RunAs       string `json:"run_as,omitempty"`
	LDAPMS      int64  `json:"ldap_ms,omitempty"`
}

// authInfo carries, via the request context, what authMiddleware
// observed, so logMiddleware can write it to the log once
// the response has been sent.
type authInfo struct {
	Scheme string // "none", "passthrough", "ldap-runas", "basic-invalid", "ldap-denied"
	User   string
	RunAs  string
	LDAPMS int64
}

type authInfoCtxKeyType struct{}

var authInfoCtxKey = authInfoCtxKeyType{}

// statusRecorder captures the HTTP status code written by the proxy, so
// it can be logged afterwards.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// ldapConfig groups the search-then-bind settings (F4) and, from
// SP-06, group lookup (the `groups` claim of the short-lived token, F78).
type ldapConfig struct {
	URL              string
	ReadonlyDN       string
	ReadonlyPassword string
	BaseDN           string
	GroupsBaseDN     string
	CacheTTL         time.Duration
}

// proxyServiceConfig groups the credentials of the service account used
// to talk to Elasticsearch once the LDAP identity is validated (F2).
type proxyServiceConfig struct {
	User     string
	Password string
}

// jwtConfig groups what is needed to issue the short-lived token (F78, SP-06):
// the proxy's private key (never shared, see spike/keys/README.md), the
// expected audience (the dummy engine) and the validity duration (5 to
// 15 min required by F78; the spike keeps the lower bound, 5 min, to
// reduce the abuse window during tests).
type jwtConfig struct {
	PrivateKey *rsa.PrivateKey
	Issuer     string
	Audience   string
	TTL        time.Duration
}

func main() {
	upstream := getenv("UPSTREAM_URL", "http://elasticsearch:9200")
	listenAddr := getenv("LISTEN_ADDR", ":9200")

	target, err := url.Parse(upstream)
	if err != nil {
		log.Fatalf("invalid UPSTREAM_URL %q: %v", upstream, err)
	}

	ldapCfg := ldapConfig{
		URL:              getenv("LDAP_URL", "ldap://openldap:389"),
		ReadonlyDN:       getenv("LDAP_READONLY_DN", "cn=readonly,dc=example,dc=org"),
		ReadonlyPassword: os.Getenv("LDAP_READONLY_PASSWORD"),
		BaseDN:           getenv("LDAP_BASE_DN", "ou=people,dc=example,dc=org"),
		GroupsBaseDN:     getenv("LDAP_GROUPS_BASE_DN", "ou=groups,dc=example,dc=org"),
		CacheTTL:         parseDuration(getenv("LDAP_CACHE_TTL", "2m")),
	}

	proxySvc := proxyServiceConfig{
		User:     getenv("PROXY_SERVICE_USER", "proxy_service"),
		Password: os.Getenv("PROXY_SERVICE_PASSWORD"),
	}
	if proxySvc.Password == "" {
		log.Fatal("PROXY_SERVICE_PASSWORD missing: required to talk to Elasticsearch with run_as (SP-03)")
	}
	if ldapCfg.ReadonlyPassword == "" {
		log.Fatal("LDAP_READONLY_PASSWORD missing: required for search-then-bind (SP-03, F4)")
	}

	// SP-03 runtime finding: POST /_security/profile/_activate (called
	// by Kibana right after login to create/activate the user
	// profile) is NOT sent with the user's Basic auth: it
	// is sent with kibana_system credentials, and carries the password
	// typed by the user in the JSON body (grant_type:
	// "password"), which Elasticsearch itself verifies against its native realm.
	// Because alice/bob/carol have no LDAP realm on the ES side (path A), this
	// password can never match: without what follows, Kibana
	// login fails with 401 on the first attempt (see the spike log).
	// Fix: a shared secret known only to the proxy and ES bootstrap
	// (never typed by the user, never LDAP) serves as the native
	// password for alice/bob/carol; the proxy substitutes it in the body of
	// this specific call, once the LDAP password has been re-checked.
	shadowPassword := os.Getenv("NATIVE_SHADOW_PASSWORD")
	if shadowPassword == "" {
		log.Fatal("NATIVE_SHADOW_PASSWORD missing: required for /_security/profile/_activate (SP-03)")
	}

	// Accounts that pass through the proxy without going through LDAP: the
	// service accounts (kibana_system, proxy_service) and the native superuser
	// (elastic), kept for fallback logins (SP-01). From SP-06,
	// these are also the accounts the proxy refuses to mint a short-lived
	// token for (F78): a token represents a real user, not a
	// service account.
	passthrough := map[string]bool{
		"elastic":       true,
		"kibana_system": true,
		proxySvc.User:   true,
	}

	// SP-06: proxy private key to sign the short-lived token (F78, F80: the
	// plugin and the engine never hold more than the public part,
	// see spike/keys/README.md). No rotation here (F81 = J2-03): a
	// single key pair for the whole spike.
	jwtPrivateKey, err := loadRSAPrivateKey(getenv("JWT_PRIVATE_KEY_PATH", "/keys/private.pem"))
	if err != nil {
		log.Fatalf("invalid JWT private key (SP-06, F78): %v", err)
	}
	jwtCfg := jwtConfig{
		PrivateKey: jwtPrivateKey,
		Issuer:     getenv("JWT_ISSUER", "spike-proxy"),
		Audience:   getenv("JWT_AUDIENCE", "spike-engine"),
		TTL:        parseDuration(getenv("JWT_TTL", "5m")),
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorLog = log.New(os.Stderr, "", log.LstdFlags)

	authCache := newLDAPAuthCache()
	profileFix := profileActivateMiddleware(proxy, ldapCfg, authCache, passthrough, shadowPassword)
	mint := mintIdentityTokenMiddleware(profileFix, ldapCfg, jwtCfg, upstream, passthrough)
	auth := authMiddleware(mint, ldapCfg, proxySvc, passthrough, authCache)
	handler := logMiddleware(auth)

	log.Printf("proxy SP-02..SP-06: listening on %s, relaying to %s, LDAP %s, short-lived token aud=%s", listenAddr, upstream, ldapCfg.URL, jwtCfg.Audience)
	if err := http.ListenAndServe(listenAddr, handler); err != nil {
		log.Fatal(err)
	}
}

// logMiddleware wraps the chain to write one JSON line per call,
// once the response has been sent (by the proxy or by a 401 denial from
// authMiddleware). It places an empty *authInfo in the context before calling
// the next handler: authMiddleware fills it, logMiddleware rereads it afterwards.
func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		info := &authInfo{Scheme: "none"}
		r = r.WithContext(context.WithValue(r.Context(), authInfoCtxKey, info))

		next.ServeHTTP(rec, r)

		entry := logEntry{
			Timestamp:   start.UTC().Format(time.RFC3339Nano),
			Method:      r.Method,
			Path:        r.URL.Path,
			Query:       r.URL.RawQuery,
			Status:      rec.status,
			DurationMS:  time.Since(start).Milliseconds(),
			Security:    isSecurityCall(r.URL.Path),
			KibanaIndex: strings.Contains(r.URL.Path, ".kibana"),
			AuthScheme:  info.Scheme,
			User:        info.User,
			RunAs:       info.RunAs,
			LDAPMS:      info.LDAPMS,
		}

		writeLog(entry)
	})
}

// authMiddleware intercepts LDAP Basic auth and replaces it with the
// service account + es-security-runas-user (F2, F4, F12). Everything else (no
// Authorization, ApiKey, Bearer, Basic of a service account) passes through
// unmodified: that is the SP-02 scope, unchanged.
func authMiddleware(next http.Handler, cfg ldapConfig, svc proxyServiceConfig, passthrough map[string]bool, cache *ldapAuthCache) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, _ := r.Context().Value(authInfoCtxKey).(*authInfo)

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Basic ") {
			// No header, ApiKey or Bearer: pass-through (SP-02).
			if info != nil {
				info.Scheme = "passthrough"
			}
			next.ServeHTTP(w, r)
			return
		}

		user, password, ok := decodeBasicAuth(authHeader)
		if !ok {
			if info != nil {
				info.Scheme = "basic-invalid"
			}
			http.Error(w, "invalid Basic Authorization", http.StatusUnauthorized)
			return
		}

		if passthrough[user] {
			// Service account or native superuser: unchanged (SP-02).
			if info != nil {
				info.Scheme = "passthrough"
				info.User = user
			}
			next.ServeHTTP(w, r)
			return
		}

		if password == "" {
			// Never an anonymous/unauthenticated bind (F7): an empty
			// password is always denied, LDAP or not.
			if info != nil {
				info.Scheme = "ldap-denied"
				info.User = user
			}
			http.Error(w, "password required", http.StatusUnauthorized)
			return
		}

		ok, ldapMS := authenticateLDAPCached(cfg, cache, user, password)

		if info != nil {
			info.User = user
			info.LDAPMS = ldapMS
		}

		if !ok {
			if info != nil {
				info.Scheme = "ldap-denied"
			}
			http.Error(w, "LDAP authentication denied", http.StatusUnauthorized)
			return
		}

		// Success: never relay the LDAP password to
		// Elasticsearch (F2, F12). The service account talks to ES and
		// impersonates the user via the run_as header.
		r.Header.Set("Authorization", basicAuthHeader(svc.User, svc.Password))
		r.Header.Set("es-security-runas-user", user)
		if info != nil {
			info.Scheme = "ldap-runas"
			info.RunAs = user
		}

		next.ServeHTTP(w, r)
	})
}

// ldapAuthenticate does a search-then-bind (F4): bind with the
// read-only account, search for the DN by uid, then bind with the supplied password.
// Returns the DN if authentication succeeds.
func ldapAuthenticate(cfg ldapConfig, username, password string) (string, error) {
	conn, err := ldap.DialURL(cfg.URL)
	if err != nil {
		return "", fmt.Errorf("LDAP connection: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.ReadonlyDN, cfg.ReadonlyPassword); err != nil {
		return "", fmt.Errorf("read-only account bind: %w", err)
	}

	// Anti-injection escaping (F7): ldap.EscapeFilter neutralizes
	// special characters in an LDAP filter.
	filter := fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(username))
	searchReq := ldap.NewSearchRequest(
		cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return "", fmt.Errorf("LDAP search: %w", err)
	}
	if len(sr.Entries) != 1 {
		return "", errors.New("user not found in the directory")
	}
	userDN := sr.Entries[0].DN

	if err := conn.Bind(userDN, password); err != nil {
		return "", fmt.Errorf("password rejected: %w", err)
	}

	return userDN, nil
}

// authenticateLDAPCached does a search-then-bind via ldapAuthenticate, unless
// a recent success for the same user/password pair is in
// cache. Returns whether authentication is valid and its duration (0 if served
// from cache). An empty password is always denied (F7).
func authenticateLDAPCached(cfg ldapConfig, cache *ldapAuthCache, user, password string) (ok bool, ldapMS int64) {
	if password == "" {
		return false, 0
	}
	start := time.Now()
	fromCache, dn := cache.check(user, password)
	var err error
	if !fromCache {
		dn, err = ldapAuthenticate(cfg, user, password)
	}
	ms := time.Since(start).Milliseconds()
	if err != nil || dn == "" {
		return false, ms
	}
	if !fromCache {
		cache.store(user, password, cfg.CacheTTL)
	}
	return true, ms
}

// profileActivateMiddleware fixes a blind spot of path A, observed while
// running the spike: POST /_security/profile/_activate is called
// by Kibana right after login, authenticated with kibana_system
// credentials (hence pass-through for authMiddleware), but carries the
// password typed by the user in the JSON body (grant_type: "password").
// Elasticsearch verifies this password itself against its native realm; yet
// alice/bob/carol have no LDAP realm on the ES side (that is the whole point of
// path A), so their real LDAP password can never match. Without
// this fix, Kibana login fails with 401 on the first attempt.
//
// Fix: for this specific endpoint, if the grant targets an LDAP
// user (not a service account), the proxy re-checks the password via
// LDAP (hot cache most of the time, since /internal/security/login
// just triggered a _authenticate run_as immediately before), then substitutes
// in the body a shared secret known only to the proxy and ES bootstrap
// (NATIVE_SHADOW_PASSWORD): never typed by the user, never
// sent to LDAP, never logged. Service accounts keep their
// grant as-is (their real ES password is already correct).
func profileActivateMiddleware(next http.Handler, cfg ldapConfig, cache *ldapAuthCache, passthrough map[string]bool, shadowPassword string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/_security/profile/_activate" {
			next.ServeHTTP(w, r)
			return
		}

		info, _ := r.Context().Value(authInfoCtxKey).(*authInfo)

		body, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			http.Error(w, "unable to read body", http.StatusBadRequest)
			return
		}

		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			// Unexpected body: leave it untouched and relay as-is
			// rather than blocking a call we do not understand.
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
			return
		}

		grantType, _ := payload["grant_type"].(string)
		username, _ := payload["username"].(string)

		if grantType != "password" || username == "" || passthrough[username] {
			// Grant of another type (access_token, id_token), or a service
			// account whose real ES password is already correct.
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
			return
		}

		password, _ := payload["password"].(string)
		ok, ldapMS := authenticateLDAPCached(cfg, cache, username, password)
		if info != nil {
			info.LDAPMS += ldapMS
			if info.User == "" {
				info.User = username
			}
		}
		if !ok {
			if info != nil {
				info.Scheme = "ldap-denied"
			}
			http.Error(w, "LDAP authentication denied", http.StatusUnauthorized)
			return
		}

		payload["password"] = shadowPassword
		newBody, err := json.Marshal(payload)
		if err != nil {
			http.Error(w, "unable to rewrite body", http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(newBody))
		r.ContentLength = int64(len(newBody))
		r.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
		if info != nil {
			info.Scheme = "ldap-profile-activate"
		}

		next.ServeHTTP(w, r)
	})
}

// mintIdentityTokenMiddleware answers, without ever relaying to Elasticsearch,
// on POST /_spike/identity-token (SP-06, F78): it issues a short-lived
// signed token (JWT RS256, TTL jwtCfg.TTL) carrying the identity already authenticated by
// authMiddleware. This is the "token requested via Elasticsearch, with
// the user's session" variant chosen first by the spike plan
// (step 6): the Kibana plugin needs no separate channel, it goes through
// the Elasticsearch client scoped to the current user (asCurrentUser).
//
// Two identity cases, depending on what authMiddleware already observed:
//   - "ldap-runas": the request carried LDAP Basic auth, already resolved and
//     rewritten as run_as. The identity is known without an extra call —
//     this is the expected path, since Kibana replays alice's
//     password on every asCurrentUser call (observed as of SP-02/SP-03).
//   - "passthrough" with no user already known: the request carried an
//     ApiKey or a Bearer (watch point documented in this ticket's
//     plan). A real user may still hide behind a
//     Kibana session ApiKey; this path introspects the identity via
//     GET /_security/_authenticate on Elasticsearch, relaying the original
//     Authorization header (never seen by this middleware otherwise). No
//     header at all: denied (401).
//
// In all cases, a service account (passthrough: elastic,
// kibana_system, proxy_service) never receives a token: a token
// represents a real user, including groups, not a technical account.
func mintIdentityTokenMiddleware(next http.Handler, cfg ldapConfig, jwtCfg jwtConfig, upstream string, passthrough map[string]bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_spike/identity-token" {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not supported, POST expected", http.StatusMethodNotAllowed)
			return
		}

		// Runtime finding (SP-06, plugin actually compiled): the official
		// Elasticsearch client used by asCurrentUser.transport.request
		// on the plugin side does a "product check" on every response and rejects
		// (ProductNotSupportedError) anything that does not carry this header —
		// including our synthetic 401/403 responses, never relayed to a
		// real Elasticsearch. Without it, the plugin sees a transport failure
		// before it can even read the error JSON body.
		w.Header().Set("X-elastic-product", "Elasticsearch")

		info, _ := r.Context().Value(authInfoCtxKey).(*authInfo)

		var user, authScheme string

		switch {
		case info != nil && info.Scheme == "ldap-runas":
			user = info.RunAs
			authScheme = "jwt-mint-basic"

		case info != nil && info.Scheme == "passthrough":
			if info.User != "" {
				// Basic auth of a service account.
				info.Scheme = "jwt-denied-service"
				http.Error(w, "service accounts do not receive a short-lived token", http.StatusForbidden)
				return
			}
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				info.Scheme = "jwt-denied-anonymous"
				http.Error(w, "authentication required to obtain a token", http.StatusUnauthorized)
				return
			}
			resolved, err := resolveIdentityViaAuthenticate(upstream, authHeader)
			if err != nil {
				log.Printf("_authenticate introspection failed (SP-06): %v", err)
				info.Scheme = "jwt-denied-apikey"
				http.Error(w, "identity not found with Elasticsearch", http.StatusUnauthorized)
				return
			}
			if passthrough[resolved] {
				info.Scheme = "jwt-denied-service"
				http.Error(w, "service accounts do not receive a short-lived token", http.StatusForbidden)
				return
			}
			user = resolved
			authScheme = "jwt-mint-apikey"

		default:
			// "none" (should not appear, authMiddleware always runs
			// first), "basic-invalid", "ldap-denied": already
			// denied further up the chain in the last two cases.
			http.Error(w, "authentication required to obtain a token", http.StatusUnauthorized)
			return
		}

		groups, err := lookupLDAPGroups(cfg, user)
		if err != nil {
			// Not blocking: the dummy engine does no group-based
			// authorization in this spike (F79 only checks
			// signature/expiration/audience); a token with an empty
			// groups list is better than a total denial on an LDAP glitch.
			log.Printf("LDAP group lookup failed for %s (SP-06): %v", user, err)
			groups = []string{}
		}

		token, err := mintJWT(jwtCfg, user, groups)
		if err != nil {
			log.Printf("token signing failed (SP-06): %v", err)
			http.Error(w, "token issuance failed", http.StatusInternalServerError)
			return
		}

		if info != nil {
			info.Scheme = authScheme
			info.User = user
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
	})
}

// resolveIdentityViaAuthenticate queries GET /_security/_authenticate on
// Elasticsearch, relaying the supplied Authorization header, to resolve
// the user behind an ApiKey or Bearer that this proxy does not decrypt
// itself. Finding to verify by running the spike (see
// spike/README.md#sp-06): SP-02/SP-03 show that Kibana instead replays
// Basic auth on asCurrentUser, so this path may never
// trigger in practice with the LDAP flow kept since SP-03.
func resolveIdentityViaAuthenticate(upstream, authHeader string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(upstream, "/")+"/_security/_authenticate", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", authHeader)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("_authenticate responded %d", resp.StatusCode)
	}

	var payload struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if payload.Username == "" {
		return "", errors.New("_authenticate response without username")
	}
	return payload.Username, nil
}

// lookupLDAPGroups looks up the groupOfNames groups of which the user is
// a member (F78: the short-lived token carries the groups, not only the
// username). Uses the search-then-bind read-only account (F4);
// no user password is needed here, unlike
// ldapAuthenticate — this is a search, not a password
// check.
func lookupLDAPGroups(cfg ldapConfig, username string) ([]string, error) {
	conn, err := ldap.DialURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("LDAP connection: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.ReadonlyDN, cfg.ReadonlyPassword); err != nil {
		return nil, fmt.Errorf("read-only account bind: %w", err)
	}

	userDN := fmt.Sprintf("uid=%s,%s", ldap.EscapeFilter(username), cfg.BaseDN)
	filter := fmt.Sprintf("(&(objectClass=groupOfNames)(member=%s))", ldap.EscapeFilter(userDN))

	searchReq := ldap.NewSearchRequest(
		cfg.GroupsBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"cn"},
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP search: %w", err)
	}

	groups := make([]string, 0, len(sr.Entries))
	for _, entry := range sr.Entries {
		if cn := entry.GetAttributeValue("cn"); cn != "" {
			groups = append(groups, cn)
		}
	}
	return groups, nil
}

// mintJWT builds the short-lived token (F78): RS256, issuer=spike-proxy (or
// JWT_ISSUER), audience=engine (JWT_AUDIENCE), subject=user, claim
// "groups", expiration in jwtCfg.TTL. Asymmetric signature: only the
// proxy holds the private key (F80: neither the plugin nor the engine needs
// it to issue, only to verify with the public key, F79).
func mintJWT(cfg jwtConfig, subject string, groups []string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":    cfg.Issuer,
		"aud":    cfg.Audience,
		"sub":    subject,
		"groups": groups,
		"iat":    jwt.NewNumericDate(now),
		"exp":    jwt.NewNumericDate(now.Add(cfg.TTL)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(cfg.PrivateKey)
}

// loadRSAPrivateKey reads an RSA private key in PEM format, PKCS#1 (what
// `openssl genrsa` produces, see spike/keys/README.md) or PKCS#8.
func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s does not contain a valid PEM block", path)
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid PKCS1 and PKCS8 keys: %w", err)
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("PEM key is not an RSA key")
	}
	return key, nil
}

// ldapAuthCache avoids an LDAP bind on every call: SP-02 measured ~145
// GET /_security/_authenticate and ~148 POST /_security/user/_has_privileges
// per login + Discover cycle. Without a cache, each would trigger a
// search-then-bind and make the Kibana UI perceptibly slower.
// Key: user + password hash (the plaintext password is
// never stored).
type ldapAuthCache struct {
	mu      sync.Mutex
	entries map[string]time.Time // key -> expiry
}

func newLDAPAuthCache() *ldapAuthCache {
	return &ldapAuthCache{entries: make(map[string]time.Time)}
}

func (c *ldapAuthCache) key(user, password string) string {
	sum := sha256.Sum256([]byte(password))
	return user + "\x00" + hex.EncodeToString(sum[:])
}

// check returns (true, user) if a valid authentication is cached
// for this user/password pair.
func (c *ldapAuthCache) check(user, password string) (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := c.key(user, password)
	expiry, ok := c.entries[k]
	if !ok {
		return false, ""
	}
	if time.Now().After(expiry) {
		delete(c.entries, k)
		return false, ""
	}
	return true, user
}

func (c *ldapAuthCache) store(user, password string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[c.key(user, password)] = time.Now().Add(ttl)
}

// decodeBasicAuth extracts the user and password from an
// "Authorization: Basic <base64>" header.
func decodeBasicAuth(header string) (user, password string, ok bool) {
	encoded := strings.TrimPrefix(header, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func basicAuthHeader(user, password string) string {
	raw := user + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
}

// isSecurityCall spots calls to the Elasticsearch security API
// (authentication, roles, privileges...), useful for SP-03 and F67.
func isSecurityCall(path string) bool {
	return strings.HasPrefix(path, "/_security") || strings.HasPrefix(path, "/_xpack/security")
}

func writeLog(entry logEntry) {
	b, err := json.Marshal(entry)
	if err != nil {
		log.Printf("logging error: %v", err)
		return
	}
	b = append(b, '\n')
	if _, err := os.Stdout.Write(b); err != nil {
		log.Printf("log write error: %v", err)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		log.Printf("invalid duration %q, falling back to 2m: %v", s, err)
		return 2 * time.Minute
	}
	return d
}
