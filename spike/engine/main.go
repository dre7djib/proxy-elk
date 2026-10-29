// Moteur factice du spike SP-06 (F78-F82) : un processus HTTP minimal,
// séparé du proxy (c'est tout l'intérêt de l'architecture décidée dans le
// plan du spike — le proxy émet, le moteur vérifie, avec des clés
// différentes). Une seule route utile, POST /whoami : vérifie le jeton
// court (signature RS256, expiration, destinataire) et renvoie l'identité
// qu'il porte. Pas d'appel à Elasticsearch, pas de question en langage
// naturel : ce n'est pas l'assistant IA (J2-06/J2-07), seulement le
// vérificateur de jeton que SP-06 doit valider. Code jetable, pas de tests.
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

// whoamiResponse est ce que le moteur renvoie une fois le jeton vérifié :
// l'identité qu'il porte, pas plus (F79 : signature, expiration,
// destinataire — pas d'autorisation par groupe dans ce spike).
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
	Reason     string // valeur courte, journalisée et renvoyée au client
}

func (e *verifyError) Error() string { return e.Reason }

func main() {
	listenAddr := getenv("LISTEN_ADDR", ":8080")
	publicKeyPath := getenv("JWT_PUBLIC_KEY_PATH", "/keys/public.pem")
	audience := getenv("JWT_AUDIENCE", "spike-engine")
	clockSkew := parseDuration(getenv("JWT_CLOCK_SKEW", "60s"))

	publicKey, err := loadRSAPublicKey(publicKeyPath)
	if err != nil {
		log.Fatalf("clé publique JWT invalide (SP-06, F79): %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/whoami", whoamiHandler(publicKey, audience, clockSkew))

	log.Printf("moteur factice SP-06 : écoute sur %s, audience attendue %q, clé publique %s, tolérance d'horloge %s",
		listenAddr, audience, publicKeyPath, clockSkew)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatal(err)
	}
}

// whoamiHandler vérifie le jeton court (F79) : méthode de signature RS256
// uniquement (pas de confusion d'algorithme), signature, expiration avec
// tolérance d'horloge configurable, et destinataire (`aud`) égal à ce
// moteur. Aucune autre vérification : ni rôle, ni ACL, ni appel réseau — un
// moteur factice ne fait que ça.
func whoamiHandler(publicKey any, audience string, clockSkew time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, &verifyError{http.StatusMethodNotAllowed, "méthode non supportée, POST attendu"})
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
			log.Printf("jeton refusé (SP-06, F79): %s", reason)
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

		log.Printf("jeton accepté (SP-06, F79): sub=%s groups=%v", resp.Subject, resp.Groups)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// classifyJWTError traduit les erreurs de la librairie jwt/v5 en motifs de
// refus lisibles (F79 : signature, expiration ou destinataire). Le détail
// exact de l'erreur reste dans les logs du moteur (jamais renvoyé au
// client ci-dessus que sous une forme résumée, pour ne pas donner d'indice
// inutile à un attaquant).
func classifyJWTError(err error) string {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return "jeton expiré"
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return "destinataire invalide"
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return "signature invalide"
	case errors.Is(err, jwt.ErrTokenMalformed):
		return "jeton malformé"
	case errors.Is(err, jwt.ErrTokenUsedBeforeIssued), errors.Is(err, jwt.ErrTokenNotValidYet):
		return "jeton pas encore valide"
	default:
		return "jeton invalide"
	}
}

func bearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", errors.New("en-tête Authorization manquant")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", errors.New("schéma d'authentification attendu: Bearer")
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if token == "" {
		return "", errors.New("jeton vide")
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
		log.Printf("durée invalide %q, repli sur 60s: %v", s, err)
		return 60 * time.Second
	}
	return d
}

func init() {
	// Message d'amorçage explicite si la clé publique attendue est absente,
	// plus parlant qu'une erreur générique de lecture de fichier au
	// démarrage (voir loadRSAPublicKey dans keys.go).
	if _, err := os.Stat(getenv("JWT_PUBLIC_KEY_PATH", "/keys/public.pem")); err != nil {
		fmt.Fprintln(os.Stderr, "avertissement: clé publique JWT pas encore présente, vérifiée au démarrage réel")
	}
}
