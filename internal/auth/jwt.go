package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JWTConfig configures a JWT verifier for machine-to-machine Bearer tokens
// (F13). It never emits tokens; it only checks those an external IdP
// already issued (not F78, the short-lived Kibana→engine identity token).
type JWTConfig struct {
	Issuer   string
	Audience string
	JWKSURL  string
	// GroupsClaim is the token claim holding the caller's groups. Defaults to "groups".
	GroupsClaim string
	// HTTPClient is used for JWKS requests. Defaults to http.DefaultClient.
	HTTPClient *http.Client
}

// JWT verifies RS256 Bearer tokens against one issuer's JWKS.
type JWT struct {
	cfg  JWTConfig
	http *http.Client

	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey
}

// NewJWT fetches cfg.JWKSURL and returns a JWT ready to verify Bearer tokens.
func NewJWT(ctx context.Context, cfg JWTConfig) (*JWT, error) {
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	j := &JWT{cfg: cfg, http: client}
	if err := j.refreshKeys(ctx); err != nil {
		return nil, fmt.Errorf("jwt jwks: %w", err)
	}
	return j, nil
}

func (j *JWT) refreshKeys(ctx context.Context) error {
	keys, err := fetchJWKS(ctx, j.http, j.cfg.JWKSURL)
	if err != nil {
		return err
	}
	j.mu.Lock()
	j.keys = keys
	j.mu.Unlock()
	return nil
}

func (j *JWT) key(kid string) *rsa.PublicKey {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.keys[kid]
}

type bearerHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type bearerClaims struct {
	Iss string          `json:"iss"`
	Sub string          `json:"sub"`
	Exp int64           `json:"exp"`
	Aud json.RawMessage `json:"aud"`
	// Email is optional: M2M tokens don't always carry one.
	Email string `json:"email"`
}

// AuthenticateBearer verifies raw (RS256, iss/aud/exp, sub required) and
// returns the caller's Identity. The JWKS is refreshed once on an unknown
// kid, same as OIDC's Provider.
func (j *JWT) AuthenticateBearer(ctx context.Context, raw string) (*Identity, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwt: malformed")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwt: malformed header")
	}
	var header bearerHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("jwt: malformed header")
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("jwt: unsupported alg %q", header.Alg)
	}

	key := j.key(header.Kid)
	if key == nil {
		if err := j.refreshKeys(ctx); err != nil {
			return nil, fmt.Errorf("jwt: unknown key id %q: %w", header.Kid, err)
		}
		key = j.key(header.Kid)
		if key == nil {
			return nil, fmt.Errorf("jwt: unknown key id %q", header.Kid)
		}
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwt: malformed signature")
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sig); err != nil {
		return nil, fmt.Errorf("jwt: invalid signature: %w", err)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt: malformed payload")
	}
	var raws map[string]json.RawMessage
	if err := json.Unmarshal(payloadJSON, &raws); err != nil {
		return nil, fmt.Errorf("jwt: malformed payload")
	}
	var claims bearerClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("jwt: malformed payload")
	}

	if claims.Iss != j.cfg.Issuer {
		return nil, fmt.Errorf("jwt: issuer mismatch")
	}
	if !audienceContains(claims.Aud, j.cfg.Audience) {
		return nil, fmt.Errorf("jwt: audience mismatch")
	}
	if claims.Exp == 0 || time.Unix(claims.Exp, 0).Before(time.Now()) {
		return nil, fmt.Errorf("jwt: expired")
	}
	if claims.Sub == "" {
		return nil, fmt.Errorf("jwt: missing sub")
	}

	return &Identity{
		Subject: claims.Sub,
		Email:   claims.Email,
		Groups:  stringSlice(raws[j.cfg.GroupsClaim]),
	}, nil
}
