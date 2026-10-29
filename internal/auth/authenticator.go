package auth

import "context"

// Method identifies how an Identity was authenticated. It rides along in
// the session for future audit use (J1-10); the ACL only ever looks at
// Identity itself.
type Method string

const (
	MethodOIDC Method = "oidc"
	MethodLDAP Method = "ldap"
	MethodJWT  Method = "jwt"
)

// PasswordAuthenticator authenticates a username/password pair into an
// Identity. OIDC's redirect flow doesn't fit this shape (there is no
// password to check), so it stays on *Provider; *LDAP satisfies this
// interface.
type PasswordAuthenticator interface {
	Authenticate(ctx context.Context, username, password string) (*Identity, error)
}

var _ PasswordAuthenticator = (*LDAP)(nil)
