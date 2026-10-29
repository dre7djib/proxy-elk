// Dummy engine for spike SP-06 (F78-F82): a minimal HTTP process,
// separate from the proxy (that is the whole point of the architecture decided in the
// spike plan — the proxy issues, the engine verifies, with different
// keys). A single useful route, POST /whoami: verifies the short-lived
// token (RS256 signature, expiration, audience) and returns the identity
// it carries. No call to Elasticsearch, no natural-language
// question: this is not the AI assistant (J2-06/J2-07), only the
// token verifier that SP-06 must validate. Throwaway code, no tests.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// whoamiResponse is what the engine returns once the token is verified:
// the identity it carries, nothing more (F79: signature, expiration,
// audience — no group-based authorization in this spike).
type whoamiResponse struct {
	Subject   string   `json:"sub"`
	Groups    []string `json:"groups"`
	Issuer    string   `json:"iss"`
	Audience  string   `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
}

type verifyError struct {
	StatusCode int
	Reason     string // short value, logged and returned to the client
}

func (e *verifyError) Error() string { return e.Reason }

func main() {
	listenAddr := getenv("LISTEN_ADDR", ":8080")
	publicKeyPath := getenv("JWT_PUBLIC_KEY_PATH", "/keys/public.pem")
	audience := getenv("JWT_AUDIENCE", "spike-engine")
	clockSkew := parseDuration(getenv("JWT_CLOCK_SKEW", "60s"))

	publicKey, err := loadRSAPublicKey(publicKeyPath)
	if err != nil {
		log.Fatalf("invalid JWT public key (SP-06, F79): %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/whoami", whoamiHandler(publicKey, audience, clockSkew))

	log.Printf("dummy engine SP-06: listening on %s, expected audience %q, public key %s, clock skew %s",
		listenAddr, audience, publicKeyPath, clockSkew)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatal(err)
	}
}

// whoamiHandler verifies the short-lived token (F79): RS256 signature
// method only (no algorithm confusion), signature, expiration with
// configurable clock skew, and audience (`aud`) equal to this
// engine. No other check: no role, no ACL, no network call — a
// dummy engine does only that.
func whoamiHandler(publicKey any, audience string, clockSkew time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, &verifyError{http.StatusMethodNotAllowed, "method not supported, POST expected"})
			return
		}

		tokenString, err := bearerToken(r)
		if err != nil {
			respondError(w, &verifyError{http.StatusUnauthorized, err.Error()})
			return
		}

		claims := jwt.MapClaims{}
		_, err = jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
			return publicKey, nil
		},
			jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
			jwt.WithAudience(audience),
			jwt.WithLeeway(clockSkew),
			jwt.WithExpirationRequired(),
		)
		if err != nil {
			reason := classifyJWTError(err)
			log.Printf("token denied (SP-06, F79): %s", reason)
			respondError(w, &verifyError{http.StatusUnauthorized, reason})
			return
		}

		resp := whoamiResponse{
			Subject:  stringClaim(claims, "sub"),
			Issuer:   stringClaim(claims, "iss"),
			Audience: stringClaim(claims, "aud"),
			Groups:   stringSliceClaim(claims, "groups"),
		}
		if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
			resp.ExpiresAt = exp.Unix()
		}
		if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
			resp.IssuedAt = iat.Unix()
		}

		log.Printf("token accepted (SP-06, F79): sub=%s groups=%v", resp.Subject, resp.Groups)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// classifyJWTError translates jwt/v5 library errors into readable
// denial reasons (F79: signature, expiration or audience). The exact
// error detail stays in the engine logs (never returned to the
// client above except in summarized form, so as not to give
// a useful hint to an attacker).
func classifyJWTError(err error) string {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return "token expired"
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return "invalid audience"
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return "invalid signature"
	case errors.Is(err, jwt.ErrTokenMalformed):
		return "malformed token"
	case errors.Is(err, jwt.ErrTokenUsedBeforeIssued), errors.Is(err, jwt.ErrTokenNotValidYet):
		return "token not yet valid"
	default:
		return "invalid token"
	}
}

func bearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", errors.New("missing Authorization header")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", errors.New("expected authentication scheme: Bearer")
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if token == "" {
		return "", errors.New("empty token")
	}
	return token, nil
}

func stringClaim(claims jwt.MapClaims, key string) string {
	v, _ := claims[key].(string)
	return v
}

func stringSliceClaim(claims jwt.MapClaims, key string) []string {
	raw, ok := claims[key].([]any)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func respondError(w http.ResponseWriter, e *verifyError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.StatusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": e.Reason})
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
		log.Printf("invalid duration %q, falling back to 60s: %v", s, err)
		return 60 * time.Second
	}
	return d
}

func init() {
	// Explicit bootstrap message if the expected public key is missing,
	// more informative than a generic file-read error at
	// startup (see loadRSAPublicKey in keys.go).
	if _, err := os.Stat(getenv("JWT_PUBLIC_KEY_PATH", "/keys/public.pem")); err != nil {
		fmt.Fprintln(os.Stderr, "warning: JWT public key not yet present, checked at actual startup")
	}
}
