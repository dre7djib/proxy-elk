package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SessionCookieName is the cookie carrying the signed session. Fixed: OIDC
// and LDAP logins share one session mechanism (F12).
const SessionCookieName = "proxy_session"

// SessionConfig configures a Sessions issuer/parser.
type SessionConfig struct {
	// Secret signs and verifies the cookie (HMAC-SHA256). Should be at
	// least 32 bytes; config.Load enforces that for the YAML-facing value.
	Secret []byte
	// TTL is how long an issued session is valid. Defaults to 8h.
	TTL time.Duration
	// Secure sets the cookie's Secure flag. False only makes sense in dev,
	// over plain HTTP.
	Secure bool
}

// sessionClaims is the cookie payload. It never carries a password.
type sessionClaims struct {
	Subject string   `json:"sub"`
	Email   string   `json:"email"`
	Groups  []string `json:"groups"`
	Method  Method   `json:"method"`
	Exp     int64    `json:"exp"`
}

// Sessions issues and validates the HMAC-signed session cookie shared by
// every login method. A nil *Sessions always fails to parse and refuses to
// issue, so leaving it unset safely disables sessions instead of panicking.
type Sessions struct {
	secret []byte
	ttl    time.Duration
	secure bool
}

// NewSessions returns a Sessions enforcing cfg.
func NewSessions(cfg SessionConfig) *Sessions {
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	return &Sessions{secret: cfg.Secret, ttl: ttl, secure: cfg.Secure}
}

// Issue sets the session cookie for id, authenticated via method. The
// password that produced id has already been discarded by the caller; it
// never reaches this function.
func (s *Sessions) Issue(w http.ResponseWriter, id Identity, method Method) error {
	if s == nil {
		return fmt.Errorf("session: sessions are disabled")
	}
	exp := time.Now().Add(s.ttl)
	claims := sessionClaims{Subject: id.Subject, Email: id.Email, Groups: id.Groups, Method: method, Exp: exp.Unix()}
	payload, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	value := encoded + "." + s.sign(encoded)
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
	})
	return nil
}

// FromRequest parses and validates the session cookie on r, rejecting a
// missing cookie, a bad signature (tampered or wrong secret), or an expired
// session.
func (s *Sessions) FromRequest(r *http.Request) (*Identity, Method, error) {
	if s == nil {
		return nil, "", fmt.Errorf("session: sessions are disabled")
	}
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, "", fmt.Errorf("session: no cookie")
	}
	encoded, sig, ok := strings.Cut(cookie.Value, ".")
	if !ok {
		return nil, "", fmt.Errorf("session: malformed cookie")
	}
	if subtle.ConstantTimeCompare([]byte(sig), []byte(s.sign(encoded))) != 1 {
		return nil, "", fmt.Errorf("session: invalid signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, "", fmt.Errorf("session: malformed payload")
	}
	var claims sessionClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, "", fmt.Errorf("session: malformed payload")
	}
	if time.Now().Unix() > claims.Exp {
		return nil, "", fmt.Errorf("session: expired")
	}
	return &Identity{Subject: claims.Subject, Email: claims.Email, Groups: claims.Groups}, claims.Method, nil
}

// Clear removes the session cookie.
func (s *Sessions) Clear(w http.ResponseWriter) {
	if s == nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

func (s *Sessions) sign(encoded string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(encoded))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
