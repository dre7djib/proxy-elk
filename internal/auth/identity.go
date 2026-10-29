package auth

// Identity is the authenticated user, independent of how they logged in.
// OIDC and LDAP both produce one so the ACL can ignore the source.
type Identity struct {
	Subject string
	Email   string
	Groups  []string
}
