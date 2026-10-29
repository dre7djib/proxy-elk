package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig configures a search-then-bind directory. BindPassword and the
// password passed to Authenticate are never logged.
type LDAPConfig struct {
	URL          string
	StartTLS     bool
	BindDN       string
	BindPassword string
	BaseDN       string
	// UserFilter must contain exactly one %s, replaced with the escaped username.
	UserFilter             string
	GroupsBaseDN           string
	CAFile                 string
	InsecureAllowPlaintext bool
}

// ldapConn is the subset of *ldap.Conn that Authenticate needs; tests
// substitute a fake implementation instead of dialing a real directory.
type ldapConn interface {
	Bind(username, password string) error
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// LDAP authenticates users against a directory with search-then-bind:
// bind as a read-only account, search for the user's DN, then bind as the
// user to check their password.
type LDAP struct {
	cfg       LDAPConfig
	tlsConfig *tls.Config
	dial      func() (ldapConn, error)
}

// NewLDAP validates cfg and prepares an LDAP ready to authenticate. It
// refuses to start against a plaintext ldap:// URL unless StartTLS or
// InsecureAllowPlaintext is set.
func NewLDAP(cfg LDAPConfig) (*LDAP, error) {
	if strings.HasPrefix(cfg.URL, "ldap://") && !cfg.StartTLS && !cfg.InsecureAllowPlaintext {
		return nil, fmt.Errorf("ldap: plaintext url requires start_tls or insecure_allow_plaintext")
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: false}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ldap: read ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ldap: ca_file has no usable certificate")
		}
		tlsConfig.RootCAs = pool
	}

	l := &LDAP{cfg: cfg, tlsConfig: tlsConfig}
	l.dial = l.dialReal
	return l, nil
}

func (l *LDAP) dialReal() (ldapConn, error) {
	conn, err := ldap.DialURL(l.cfg.URL, ldap.DialWithTLSConfig(l.tlsConfig))
	if err != nil {
		return nil, err
	}
	if l.cfg.StartTLS {
		if err := conn.StartTLS(l.tlsConfig); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// Authenticate runs search-then-bind for username/password and returns the
// user's Identity (subject, email, flat group CNs). An empty password is
// refused before any network connection (F7). The password only exists for
// the duration of this call; it is never logged, cached or stored.
func (l *LDAP) Authenticate(ctx context.Context, username, password string) (*Identity, error) {
	if password == "" {
		return nil, fmt.Errorf("ldap: empty password")
	}

	conn, err := l.dial()
	if err != nil {
		return nil, fmt.Errorf("ldap: connect: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(l.cfg.BindDN, l.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("ldap: readonly bind: %w", err)
	}

	// EscapeFilter neutralizes LDAP filter metacharacters in username (F7):
	// an attacker cannot inject "*)(uid=*" to widen the search.
	filter := fmt.Sprintf(l.cfg.UserFilter, ldap.EscapeFilter(username))
	searchReq := ldap.NewSearchRequest(
		l.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		filter,
		[]string{"mail"},
		nil,
	)
	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("ldap: search: %w", err)
	}
	if len(sr.Entries) != 1 {
		return nil, fmt.Errorf("ldap: user not found")
	}
	entry := sr.Entries[0]
	userDN := entry.DN
	email := entry.GetAttributeValue("mail")

	if err := conn.Bind(userDN, password); err != nil {
		return nil, fmt.Errorf("ldap: password rejected")
	}

	// Re-bind as the read-only account: the user bind above replaced the
	// connection's authenticated identity, and group search must not run as
	// the user (who may lack read access to the groups tree).
	if err := conn.Bind(l.cfg.BindDN, l.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("ldap: readonly re-bind: %w", err)
	}
	groupFilter := fmt.Sprintf("(&(objectClass=groupOfNames)(member=%s))", ldap.EscapeFilter(userDN))
	groupsReq := ldap.NewSearchRequest(
		l.cfg.GroupsBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		groupFilter,
		[]string{"cn"},
		nil,
	)
	gr, err := conn.Search(groupsReq)
	if err != nil {
		return nil, fmt.Errorf("ldap: groups search: %w", err)
	}
	groups := make([]string, 0, len(gr.Entries))
	for _, e := range gr.Entries {
		if cn := e.GetAttributeValue("cn"); cn != "" {
			groups = append(groups, cn)
		}
	}

	return &Identity{Subject: username, Email: email, Groups: groups}, nil
}
