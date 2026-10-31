package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// ctxKeyCredentials mirrors gokrb5's own unexported SPNEGO context key
// (spnego.ctxCredentials = "github.com/jcmturner/gokrb5/v8/ctxCredentials").
// There is no exported accessor for the credentials AcceptSecContext
// places on the context, so the key — a plain string, matched by value,
// not by type identity — is reproduced here.
const ctxKeyCredentials = "github.com/jcmturner/gokrb5/v8/ctxCredentials"

// KerberosConfig configures SPNEGO/Kerberos authentication via a keytab.
type KerberosConfig struct {
	KeytabFile       string
	ServicePrincipal string
	Realm            string
}

// Kerberos validates a SPNEGO "Negotiate" ticket against an in-memory
// keytab — accepting an AP-REQ never talks to the KDC, so the proxy
// container needs no krb5.conf — then resolves the client principal's
// groups via Lookup, since Kerberos carries no password for Authenticate's
// bind-as-user step.
type Kerberos struct {
	cfg KerberosConfig
	kt  *keytab.Keytab

	// Lookup resolves the ticket's username (left of '@') to an Identity,
	// normally *LDAP.Lookup.
	Lookup func(ctx context.Context, username string) (*Identity, error)

	// Accept validates a base64 Negotiate token and returns the client's
	// username and realm. NewKerberos sets it to the real gokrb5
	// keytab/SPNEGO check; tests (here and in internal/es) replace it to
	// exercise the 401/Negotiate and realm/Lookup logic without a KDC.
	Accept func(token string) (username, realm string, err error)
}

// NewKerberos loads cfg.KeytabFile and returns a Kerberos ready to
// validate tickets for cfg.ServicePrincipal/cfg.Realm.
func NewKerberos(cfg KerberosConfig, lookup func(ctx context.Context, username string) (*Identity, error)) (*Kerberos, error) {
	kt, err := keytab.Load(cfg.KeytabFile)
	if err != nil {
		return nil, fmt.Errorf("kerberos: load keytab: %w", err)
	}
	k := &Kerberos{cfg: cfg, kt: kt, Lookup: lookup}
	k.Accept = k.acceptToken
	return k, nil
}

// NewKerberosForTest returns a Kerberos with no keytab loaded, for tests
// (here and in internal/es) that drive Accept and Lookup directly
// instead of a real ticket/KDC.
func NewKerberosForTest(realm string) *Kerberos {
	return &Kerberos{cfg: KerberosConfig{Realm: realm}}
}

func (k *Kerberos) acceptToken(token string) (username, realm string, err error) {
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", "", fmt.Errorf("kerberos: malformed token")
	}
	var st spnego.SPNEGOToken
	if err := st.Unmarshal(raw); err != nil {
		return "", "", fmt.Errorf("kerberos: invalid token")
	}
	// DecodePAC(false): PAC is an Active Directory extension this demo's
	// MIT KDC still attaches authorization-data for; gokrb5 can't parse
	// it as a Windows PAC and rejects the whole ticket otherwise
	// ("PAC Info Buffers does not contain a KerbValidationInfo",
	// confirmed against a real KDC). Lookup resolves groups via LDAP
	// regardless, so nothing here ever needed PAC data.
	svc := spnego.SPNEGOService(k.kt, service.DecodePAC(false))
	ok, ctx, status := svc.AcceptSecContext(&st)
	if !ok || status.Code != gssapi.StatusComplete {
		return "", "", fmt.Errorf("kerberos: ticket rejected: %v", status)
	}
	creds, ok := ctx.Value(ctxKeyCredentials).(*credentials.Credentials)
	if !ok {
		return "", "", fmt.Errorf("kerberos: no credentials in context")
	}
	return creds.UserName(), creds.Domain(), nil
}

// Authenticate validates r's Negotiate token and resolves the caller's
// groups via Lookup. It never contacts the KDC. A missing header, a
// rejected ticket, a realm other than cfg.Realm, or a username absent
// from Lookup's directory are all reported identically — the caller
// never learns which.
func (k *Kerberos) Authenticate(r *http.Request) (*Identity, error) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Negotiate ")
	if !ok || token == "" {
		return nil, fmt.Errorf("kerberos: no negotiate token")
	}
	username, realm, err := k.Accept(token)
	if err != nil {
		return nil, err
	}
	if realm != k.cfg.Realm {
		return nil, fmt.Errorf("kerberos: unexpected realm %q", realm)
	}
	id, err := k.Lookup(r.Context(), username)
	if err != nil {
		return nil, fmt.Errorf("kerberos: %w", err)
	}
	return id, nil
}

// Middleware serves 401 + "WWW-Authenticate: Negotiate" for a request
// with no valid ticket, and otherwise calls inner with the resolved
// Identity attached to the request context (see KerberosIdentity).
func (k *Kerberos) Middleware(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := k.Authenticate(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Negotiate")
			http.Error(w, "kerberos authentication required", http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), kerberosIdentityKey{}, id)))
	})
}

type kerberosIdentityKey struct{}

// KerberosIdentity returns the Identity Middleware attached to ctx, if any.
func KerberosIdentity(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(kerberosIdentityKey{}).(*Identity)
	return id, ok
}
