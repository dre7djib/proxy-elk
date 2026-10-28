// Proxy du spike SP-02/SP-03 : un reverse proxy entre Kibana et
// Elasticsearch, qui journalise chaque appel en JSON sur stdout (SP-02) et,
// depuis SP-03, valide les logins LDAP (search-then-bind) puis parle à
// Elasticsearch avec un compte de service en usurpant l'identité de
// l'utilisateur (`es-security-runas-user`, piste A du spike). Les appels des
// comptes de service (kibana_system, elastic, proxy_service) et tout ce qui
// n'est pas du Basic auth (ApiKey, Bearer, pas d'en-tête) traversent sans
// modification. Code jetable : pas de tests, ACL/J1 hors périmètre.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
)

// logEntry est une ligne du journal des appels (une par requête).
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

// authInfo porte, via le contexte de la requête, ce que l'authMiddleware a
// constaté, pour que logMiddleware puisse l'écrire dans le journal une fois
// la réponse renvoyée.
type authInfo struct {
	Scheme string // "none", "passthrough", "ldap-runas", "basic-invalid", "ldap-denied"
	User   string
	RunAs  string
	LDAPMS int64
}

type authInfoCtxKeyType struct{}

var authInfoCtxKey = authInfoCtxKeyType{}

// statusRecorder capture le code de statut HTTP écrit par le proxy, pour
// pouvoir le journaliser après coup.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// ldapConfig regroupe les paramètres du search-then-bind (F4).
type ldapConfig struct {
	URL              string
	ReadonlyDN       string
	ReadonlyPassword string
	BaseDN           string
	CacheTTL         time.Duration
}

// proxyServiceConfig regroupe les identifiants du compte de service utilisé
// pour parler à Elasticsearch une fois l'identité LDAP validée (F2).
type proxyServiceConfig struct {
	User     string
	Password string
}

func main() {
	upstream := getenv("UPSTREAM_URL", "http://elasticsearch:9200")
	listenAddr := getenv("LISTEN_ADDR", ":9200")

	target, err := url.Parse(upstream)
	if err != nil {
		log.Fatalf("UPSTREAM_URL invalide %q: %v", upstream, err)
	}

	ldapCfg := ldapConfig{
		URL:              getenv("LDAP_URL", "ldap://openldap:389"),
		ReadonlyDN:       getenv("LDAP_READONLY_DN", "cn=readonly,dc=example,dc=org"),
		ReadonlyPassword: os.Getenv("LDAP_READONLY_PASSWORD"),
		BaseDN:           getenv("LDAP_BASE_DN", "ou=people,dc=example,dc=org"),
		CacheTTL:         parseDuration(getenv("LDAP_CACHE_TTL", "2m")),
	}

	proxySvc := proxyServiceConfig{
		User:     getenv("PROXY_SERVICE_USER", "proxy_service"),
		Password: os.Getenv("PROXY_SERVICE_PASSWORD"),
	}
	if proxySvc.Password == "" {
		log.Fatal("PROXY_SERVICE_PASSWORD manquant : requis pour parler à Elasticsearch avec run_as (SP-03)")
	}
	if ldapCfg.ReadonlyPassword == "" {
		log.Fatal("LDAP_READONLY_PASSWORD manquant : requis pour le search-then-bind (SP-03, F4)")
	}

	// Constat d'exécution SP-03 : POST /_security/profile/_activate (appelé
	// par Kibana juste après le login pour créer/activer le profil
	// utilisateur) n'est PAS envoyé avec le Basic auth de l'utilisateur : il
	// est envoyé avec les identifiants de kibana_system, et porte le mot de
	// passe tapé par l'utilisateur dans le corps JSON (grant_type:
	// "password"), qu'Elasticsearch vérifie lui-même contre son realm natif.
	// Comme alice/bob/carol n'ont pas de realm LDAP côté ES (piste A), ce
	// mot de passe ne peut jamais correspondre : sans ce qui suit, le login
	// Kibana échoue en 401 dès le premier essai (voir le journal du spike).
	// Correctif : un secret partagé connu seulement du proxy et du bootstrap
	// ES (jamais tapé par l'utilisateur, jamais LDAP) sert de mot de passe
	// natif pour alice/bob/carol ; le proxy le substitue dans le corps de
	// cet appel précis, une fois le mot de passe LDAP revérifié.
	shadowPassword := os.Getenv("NATIVE_SHADOW_PASSWORD")
	if shadowPassword == "" {
		log.Fatal("NATIVE_SHADOW_PASSWORD manquant : requis pour /_security/profile/_activate (SP-03)")
	}

	// Comptes qui traversent le proxy sans passer par le LDAP : les comptes
	// de service (kibana_system, proxy_service) et le superutilisateur natif
	// (elastic), conservé pour les logins de secours (SP-01).
	passthrough := map[string]bool{
		"elastic":       true,
		"kibana_system": true,
		proxySvc.User:   true,
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorLog = log.New(os.Stderr, "", log.LstdFlags)

	authCache := newLDAPAuthCache()
	profileFix := profileActivateMiddleware(proxy, ldapCfg, authCache, passthrough, shadowPassword)
	auth := authMiddleware(profileFix, ldapCfg, proxySvc, passthrough, authCache)
	handler := logMiddleware(auth)

	log.Printf("proxy SP-03 : écoute sur %s, relaie vers %s, LDAP %s", listenAddr, upstream, ldapCfg.URL)
	if err := http.ListenAndServe(listenAddr, handler); err != nil {
		log.Fatal(err)
	}
}

// logMiddleware enveloppe la chaîne pour écrire une ligne JSON par appel,
// une fois la réponse renvoyée (par le proxy ou par un refus 401 de
// authMiddleware). Il pose un *authInfo vide dans le contexte avant d'appeler
// la suite : authMiddleware le remplit, logMiddleware le relit après coup.
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

// authMiddleware intercepte le Basic auth LDAP et le remplace par le compte
// de service + es-security-runas-user (F2, F4, F12). Tout le reste (pas
// d'Authorization, ApiKey, Bearer, Basic d'un compte de service) traverse
// sans modification : c'est le périmètre de SP-02, inchangé.
func authMiddleware(next http.Handler, cfg ldapConfig, svc proxyServiceConfig, passthrough map[string]bool, cache *ldapAuthCache) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, _ := r.Context().Value(authInfoCtxKey).(*authInfo)

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Basic ") {
			// Pas d'en-tête, ApiKey ou Bearer : passe-plat (SP-02).
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
			http.Error(w, "Authorization Basic invalide", http.StatusUnauthorized)
			return
		}

		if passthrough[user] {
			// Compte de service ou superutilisateur natif : inchangé (SP-02).
			if info != nil {
				info.Scheme = "passthrough"
				info.User = user
			}
			next.ServeHTTP(w, r)
			return
		}

		if password == "" {
			// Jamais de bind anonyme/non authentifié (F7) : un mot de passe
			// vide est toujours refusé, LDAP ou pas.
			if info != nil {
				info.Scheme = "ldap-denied"
				info.User = user
			}
			http.Error(w, "mot de passe requis", http.StatusUnauthorized)
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
			http.Error(w, "authentification LDAP refusée", http.StatusUnauthorized)
			return
		}

		// Succès : on ne relaie jamais le mot de passe LDAP vers
		// Elasticsearch (F2, F12). Le compte de service parle à ES et
		// usurpe l'identité de l'utilisateur via l'en-tête run_as.
		r.Header.Set("Authorization", basicAuthHeader(svc.User, svc.Password))
		r.Header.Set("es-security-runas-user", user)
		if info != nil {
			info.Scheme = "ldap-runas"
			info.RunAs = user
		}

		next.ServeHTTP(w, r)
	})
}

// ldapAuthenticate fait un search-then-bind (F4) : bind avec le compte de
// lecture, recherche du DN par uid, puis bind avec le mot de passe fourni.
// Retourne le DN si l'authentification réussit.
func ldapAuthenticate(cfg ldapConfig, username, password string) (string, error) {
	conn, err := ldap.DialURL(cfg.URL)
	if err != nil {
		return "", fmt.Errorf("connexion LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.ReadonlyDN, cfg.ReadonlyPassword); err != nil {
		return "", fmt.Errorf("bind du compte de lecture: %w", err)
	}

	// Échappement anti-injection (F7) : ldap.EscapeFilter neutralise les
	// caractères spéciaux d'un filtre LDAP.
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
		return "", fmt.Errorf("recherche LDAP: %w", err)
	}
	if len(sr.Entries) != 1 {
		return "", errors.New("utilisateur introuvable dans l'annuaire")
	}
	userDN := sr.Entries[0].DN

	if err := conn.Bind(userDN, password); err != nil {
		return "", fmt.Errorf("mot de passe refusé: %w", err)
	}

	return userDN, nil
}

// authenticateLDAPCached fait un search-then-bind via ldapAuthenticate, sauf
// si un succès récent pour le même couple utilisateur/mot de passe est en
// cache. Renvoie si l'authentification est valide et sa durée (0 si servie
// par le cache). Un mot de passe vide est toujours refusé (F7).
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

// profileActivateMiddleware corrige un angle mort de la piste A, constaté en
// faisant tourner le spike : POST /_security/profile/_activate est appelé
// par Kibana juste après le login, authentifié avec les identifiants de
// kibana_system (donc passe-plat pour authMiddleware), mais porte le mot de
// passe tapé par l'utilisateur dans le corps JSON (grant_type: "password").
// Elasticsearch vérifie ce mot de passe lui-même contre son realm natif ; or
// alice/bob/carol n'ont pas de realm LDAP côté ES (c'est tout le principe de
// la piste A), donc leur vrai mot de passe LDAP ne peut jamais matcher. Sans
// ce correctif, le login Kibana échoue en 401 dès le premier essai.
//
// Correctif : pour ce point d'entrée précis, si le grant vise un utilisateur
// LDAP (pas un compte de service), le proxy revérifie le mot de passe par
// LDAP (cache chaud la plupart du temps, puisque /internal/security/login
// vient de déclencher un _authenticate run_as juste avant), puis substitue
// dans le corps un secret partagé connu seulement du proxy et du bootstrap
// ES (NATIVE_SHADOW_PASSWORD) : jamais tapé par l'utilisateur, jamais
// transmis à LDAP, jamais journalisé. Les comptes de service gardent leur
// grant tel quel (leur mot de passe ES réel est déjà le bon).
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
			http.Error(w, "lecture du corps impossible", http.StatusBadRequest)
			return
		}

		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			// Corps inattendu : on ne touche à rien, on relaie tel quel
			// plutôt que de bloquer un appel qu'on ne comprend pas.
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
			return
		}

		grantType, _ := payload["grant_type"].(string)
		username, _ := payload["username"].(string)

		if grantType != "password" || username == "" || passthrough[username] {
			// Grant d'un autre type (access_token, id_token), ou compte de
			// service dont le vrai mot de passe ES est déjà correct.
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
			http.Error(w, "authentification LDAP refusée", http.StatusUnauthorized)
			return
		}

		payload["password"] = shadowPassword
		newBody, err := json.Marshal(payload)
		if err != nil {
			http.Error(w, "réécriture du corps impossible", http.StatusInternalServerError)
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

// ldapAuthCache évite un bind LDAP à chaque appel : SP-02 a mesuré ~145
// GET /_security/_authenticate et ~148 POST /_security/user/_has_privileges
// par cycle connexion + Discover. Sans cache, chacun déclencherait un
// search-then-bind et rendrait l'UI de Kibana perceptiblement plus lente.
// Clé : utilisateur + hash du mot de passe (le mot de passe en clair n'est
// jamais conservé).
type ldapAuthCache struct {
	mu      sync.Mutex
	entries map[string]time.Time // clé -> expiration
}

func newLDAPAuthCache() *ldapAuthCache {
	return &ldapAuthCache{entries: make(map[string]time.Time)}
}

func (c *ldapAuthCache) key(user, password string) string {
	sum := sha256.Sum256([]byte(password))
	return user + "\x00" + hex.EncodeToString(sum[:])
}

// check renvoie (true, user) si une authentification valide est en cache
// pour ce couple utilisateur/mot de passe.
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

// decodeBasicAuth extrait l'utilisateur et le mot de passe d'un en-tête
// "Authorization: Basic <base64>".
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

// isSecurityCall repère les appels à l'API de sécurité d'Elasticsearch
// (authentification, rôles, privilèges...), utile pour SP-03 et F67.
func isSecurityCall(path string) bool {
	return strings.HasPrefix(path, "/_security") || strings.HasPrefix(path, "/_xpack/security")
}

func writeLog(entry logEntry) {
	b, err := json.Marshal(entry)
	if err != nil {
		log.Printf("erreur de journalisation: %v", err)
		return
	}
	b = append(b, '\n')
	if _, err := os.Stdout.Write(b); err != nil {
		log.Printf("erreur d'écriture du journal: %v", err)
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
		log.Printf("durée invalide %q, repli sur 2m: %v", s, err)
		return 2 * time.Minute
	}
	return d
}
