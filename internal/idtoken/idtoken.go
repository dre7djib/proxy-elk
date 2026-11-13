// Package idtoken issues and verifies the short identity JWT (RS256) the
// proxy hands to Kibana so the engine knows which user is calling.
// The Verifier holds public keys only.
package idtoken

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	MinTTL = 5 * time.Minute
	MaxTTL = 15 * time.Minute
	// DefaultSkew is the verifier's default clock-skew tolerance (F79).
	DefaultSkew = 60 * time.Second
)

var b64 = base64.RawURLEncoding

// Key is one signing key. The first Key of an Issuer signs; all verify.
type Key struct {
	KID     string
	Private *rsa.PrivateKey
}

// ParsePrivateKey reads a PKCS#1 or PKCS#8 RSA PEM key of at least 2048 bits.
func ParsePrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("not PEM")
	}
	k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		any, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, errors.New("not a PKCS#1 or PKCS#8 private key")
		}
		var ok bool
		if k, ok = any.(*rsa.PrivateKey); !ok {
			return nil, errors.New("not an RSA key")
		}
	}
	if k.N.BitLen() < 2048 {
		return nil, errors.New("RSA key must be at least 2048 bits")
	}
	return k, nil
}

// Issuer signs identity tokens.
type Issuer struct {
	iss, aud string
	ttl      time.Duration
	keys     []Key
	now      func() time.Time
}

// NewIssuer needs one or two keys (rotation) and a TTL within 5–15 min.
func NewIssuer(iss, aud string, ttl time.Duration, keys []Key) (*Issuer, error) {
	if iss == "" || aud == "" {
		return nil, errors.New("issuer and audience are required")
	}
	if ttl < MinTTL || ttl > MaxTTL {
		return nil, fmt.Errorf("ttl must be between %s and %s", MinTTL, MaxTTL)
	}
	if len(keys) < 1 || len(keys) > 2 {
		return nil, errors.New("1 or 2 keys required")
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if k.KID == "" || k.Private == nil || seen[k.KID] {
			return nil, errors.New("each key needs a unique kid and a private key")
		}
		seen[k.KID] = true
	}
	return &Issuer{iss: iss, aud: aud, ttl: ttl, keys: keys, now: time.Now}, nil
}

// Sign returns a JWT for subject and groups, signed with the first key.
func (i *Issuer) Sign(subject string, groups []string) (string, error) {
	if subject == "" {
		return "", errors.New("empty subject")
	}
	if groups == nil {
		groups = []string{}
	}
	now := i.now()
	k := i.keys[0]
	head, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": k.KID})
	body, _ := json.Marshal(map[string]any{
		"sub": subject, "groups": groups, "iss": i.iss, "aud": i.aud,
		"iat": now.Unix(), "exp": now.Add(i.ttl).Unix(),
	})
	signing := b64.EncodeToString(head) + "." + b64.EncodeToString(body)
	h := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(nil, k.Private, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64.EncodeToString(sig), nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// JWKS serializes the public keys only (kty, kid, n, e, alg, use).
func (i *Issuer) JWKS() ([]byte, error) {
	set := struct {
		Keys []jwk `json:"keys"`
	}{Keys: []jwk{}}
	for _, k := range i.keys {
		pub := k.Private.PublicKey
		set.Keys = append(set.Keys, jwk{
			Kty: "RSA", Kid: k.KID, Alg: "RS256", Use: "sig",
			N: b64.EncodeToString(pub.N.Bytes()),
			E: b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	return json.Marshal(set)
}

// Claims are the verified token contents.
type Claims struct {
	Subject string
	Groups  []string
}

// Verifier checks tokens with public keys only.
type Verifier struct {
	iss, aud string
	skew     time.Duration
	keys     map[string]*rsa.PublicKey
	now      func() time.Time
}

// NewVerifier builds a verifier from a JWKS document (what GET
// /identity/jwks serves). skew <= 0 means DefaultSkew.
func NewVerifier(iss, aud string, skew time.Duration, jwks []byte) (*Verifier, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	if skew <= 0 {
		skew = DefaultSkew
	}
	v := &Verifier{iss: iss, aud: aud, skew: skew, keys: map[string]*rsa.PublicKey{}, now: time.Now}
	for _, k := range set.Keys {
		n, err1 := b64.DecodeString(k.N)
		e, err2 := b64.DecodeString(k.E)
		if k.Kty != "RSA" || k.Kid == "" || err1 != nil || err2 != nil {
			return nil, errors.New("jwks: invalid RSA key")
		}
		v.keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if len(v.keys) == 0 {
		return nil, errors.New("jwks: no keys")
	}
	return v, nil
}

// Verify refuses any token that is not a valid, unexpired RS256 token
// from the expected issuer for the expected audience.
func (v *Verifier) Verify(raw string) (*Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("idtoken: malformed")
	}
	var head struct{ Alg, Kid string }
	if err := decodeJSON(parts[0], &head); err != nil {
		return nil, errors.New("idtoken: bad header")
	}
	if head.Alg != "RS256" {
		return nil, errors.New("idtoken: alg must be RS256")
	}
	pub, ok := v.keys[head.Kid]
	if !ok {
		return nil, errors.New("idtoken: unknown kid")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("idtoken: bad signature")
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig) != nil {
		return nil, errors.New("idtoken: bad signature")
	}
	var c struct {
		Sub    string   `json:"sub"`
		Groups []string `json:"groups"`
		Iss    string   `json:"iss"`
		Aud    string   `json:"aud"`
		Exp    *int64   `json:"exp"`
	}
	if err := decodeJSON(parts[1], &c); err != nil {
		return nil, errors.New("idtoken: bad payload")
	}
	switch {
	case c.Iss != v.iss:
		return nil, errors.New("idtoken: wrong issuer")
	case c.Aud != v.aud:
		return nil, errors.New("idtoken: wrong audience")
	case c.Exp == nil || !v.now().Before(time.Unix(*c.Exp, 0).Add(v.skew)):
		return nil, errors.New("idtoken: expired")
	case c.Sub == "":
		return nil, errors.New("idtoken: empty subject")
	}
	return &Claims{Subject: c.Sub, Groups: c.Groups}, nil
}

func decodeJSON(seg string, v any) error {
	b, err := b64.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
