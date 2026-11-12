package es

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
)

// activate fixes a blind spot found while running the spike
// (spike/proxy/main.go): POST /_security/profile/_activate is called by
// Kibana right after login, authenticated with kibana_system credentials
// (Passthrough), but carries the password the user typed in the JSON
// body (grant_type: "password"), which Elasticsearch checks itself
// against its native realm. LDAP users have no native-realm entry with
// that password, so without this fix the first Kibana login always fails
// with 401. Fix: re-verify the password via LDAP (served from bindCache
// most of the time, since /internal/security/login just triggered the
// same bind), then substitute ShadowPassword — a secret known only to
// the proxy and the ES bootstrap, never typed by the user, never sent to
// LDAP. A grant of another type, or one naming a Passthrough account
// (whose real ES password is already correct), is relayed unchanged.
func (rl *relay) activate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		http.Error(w, "unable to read body", http.StatusBadRequest)
		return
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		rl.proxy.ServeHTTP(w, r)
		return
	}

	grantType, _ := payload["grant_type"].(string)
	username, _ := payload["username"].(string)
	if grantType != "password" || username == "" || rl.cfg.Passthrough[username] {
		r.Body = io.NopCloser(bytes.NewReader(body))
		rl.proxy.ServeHTTP(w, r)
		return
	}

	password, _ := payload["password"].(string)
	// Kerberos has no LDAP password to re-verify: its /auth/kibana SSO
	// (kibana_sso.go) logs into Kibana with ShadowPassword directly, so
	// it already arrives here unchanged. A constant-time match skips the
	// LDAP rebind; a real LDAP password never equals the shadow (a
	// separate secret), so this never widens what an LDAP login accepts.
	if subtle.ConstantTimeCompare([]byte(password), []byte(rl.cfg.ShadowPassword)) != 1 {
		if _, err := rl.ldapBind(r, username, password); err != nil {
			http.Error(w, "LDAP authentication denied", http.StatusUnauthorized)
			return
		}
	}

	payload["password"] = rl.cfg.ShadowPassword
	newBody, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "unable to rewrite body", http.StatusInternalServerError)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(newBody))
	r.ContentLength = int64(len(newBody))
	r.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
	rl.proxy.ServeHTTP(w, r)
}
