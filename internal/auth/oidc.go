package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OIDCConfig configures a Provider.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	// GroupsClaim is the ID token claim holding the user's groups. Defaults to "groups".
	GroupsClaim string
	// HTTPClient is used for discovery, JWKS and token requests. Defaults to http.DefaultClient.
	HTTPClient *http.Client
}

// metadata is the subset of OpenID Provider metadata the proxy needs.
type metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Provider performs the OIDC authorization code flow against one issuer and
// validates the ID tokens it returns.
type Provider struct {
	cfg  OIDCConfig
	meta metadata
	http *http.Client

	keys map[string]*rsa.PublicKey
}

// Discover fetches the issuer's discovery document and JWKS, and returns a
// Provider ready to drive the login flow.
func Discover(ctx context.Context, cfg OIDCConfig) (*Provider, error) {
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}

	meta, err := fetchJSON[metadata](ctx, client, strings.TrimRight(cfg.Issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	if meta.Issuer != cfg.Issuer {
		return nil, fmt.Errorf("oidc discovery: issuer mismatch: got %q want %q", meta.Issuer, cfg.Issuer)
	}
	if meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" || meta.JWKSURI == "" {
		return nil, fmt.Errorf("oidc discovery: incomplete metadata")
	}

	p := &Provider{cfg: cfg, meta: *meta, http: client}
	if err := p.refreshKeys(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Provider) refreshKeys(ctx context.Context) error {
	keys, err := fetchJWKS(ctx, p.http, p.meta.JWKSURI)
	if err != nil {
		return fmt.Errorf("oidc jwks: %w", err)
	}
	p.keys = keys
	return nil
}

// AuthCodeURL builds the authorization endpoint URL for an authorization
// code request carrying the given state and nonce.
func (p *Provider) AuthCodeURL(state, nonce string) string {
	scopes := p.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {p.cfg.ClientID},
		"redirect_uri":  {p.cfg.RedirectURL},
		"scope":         {strings.Join(scopes, " ")},
		"state":         {state},
		"nonce":         {nonce},
	}
	return p.meta.AuthorizationEndpoint + "?" + q.Encode()
}

// tokenResponse is the token endpoint's JSON response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// Exchange trades an authorization code for tokens and validates the
// returned ID token against the expected nonce, returning the caller's
// Identity.
func (p *Provider) Exchange(ctx context.Context, code, nonce string) (Identity, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.cfg.RedirectURL},
		"client_id":     {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.meta.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Identity{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.http.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("oidc token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Identity{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Identity{}, fmt.Errorf("oidc token exchange: status %d: %s", resp.StatusCode, body)
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return Identity{}, fmt.Errorf("oidc token exchange: %w", err)
	}
	if tok.IDToken == "" {
		return Identity{}, fmt.Errorf("oidc token exchange: no id_token in response")
	}
	return p.verifyIDToken(tok.IDToken, nonce)
}

type idTokenHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type idTokenClaims struct {
	Iss   string          `json:"iss"`
	Sub   string          `json:"sub"`
	Email string          `json:"email"`
	Nonce string          `json:"nonce"`
	Exp   int64           `json:"exp"`
	Aud   json.RawMessage `json:"aud"`
}

func (p *Provider) verifyIDToken(raw, wantNonce string) (Identity, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Identity{}, fmt.Errorf("oidc id_token: malformed")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Identity{}, fmt.Errorf("oidc id_token: malformed header")
	}
	var header idTokenHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return Identity{}, fmt.Errorf("oidc id_token: malformed header")
	}
	if header.Alg != "RS256" {
		return Identity{}, fmt.Errorf("oidc id_token: unsupported alg %q", header.Alg)
	}
	key, ok := p.keys[header.Kid]
	if !ok {
		return Identity{}, fmt.Errorf("oidc id_token: unknown key id %q", header.Kid)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Identity{}, fmt.Errorf("oidc id_token: malformed signature")
	}
	signingInput := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sig); err != nil {
		return Identity{}, fmt.Errorf("oidc id_token: invalid signature: %w", err)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Identity{}, fmt.Errorf("oidc id_token: malformed payload")
	}
	var raws map[string]json.RawMessage
	if err := json.Unmarshal(payloadJSON, &raws); err != nil {
		return Identity{}, fmt.Errorf("oidc id_token: malformed payload")
	}
	var claims idTokenClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return Identity{}, fmt.Errorf("oidc id_token: malformed payload")
	}

	if claims.Iss != p.cfg.Issuer {
		return Identity{}, fmt.Errorf("oidc id_token: issuer mismatch")
	}
	if !audienceContains(claims.Aud, p.cfg.ClientID) {
		return Identity{}, fmt.Errorf("oidc id_token: audience mismatch")
	}
	if claims.Exp == 0 || time.Unix(claims.Exp, 0).Before(time.Now()) {
		return Identity{}, fmt.Errorf("oidc id_token: expired")
	}
	if claims.Nonce != wantNonce {
		return Identity{}, fmt.Errorf("oidc id_token: nonce mismatch")
	}
	if claims.Sub == "" {
		return Identity{}, fmt.Errorf("oidc id_token: missing sub")
	}

	return Identity{
		Subject: claims.Sub,
		Email:   claims.Email,
		Groups:  stringSlice(raws[p.cfg.GroupsClaim]),
	}, nil
}

// NewState returns a random URL-safe string suitable for the state and nonce
// parameters of an authorization request.
func NewState() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
