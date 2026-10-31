package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// adMatchingRuleInChain is the AD-specific OID that makes a group search
// resolve nested membership (LDAP_MATCHING_RULE_IN_CHAIN), instead of only
// direct members.
const adMatchingRuleInChain = "1.2.840.113556.1.4.1941"

// LDAPConfig configures a search-then-bind directory. BindPassword and the
// password passed to Authenticate are never logged.
type LDAPConfig struct {
	// URL is a single directory address. URLs, if non-empty, takes
	// precedence and is tried in order on a connection or StartTLS failure.
	URL      string
	URLs     []string
	StartTLS bool

	BindDN       string
	BindPassword string
	BaseDN       string
	// UserFilter must contain exactly one %s, replaced with the escaped username.
	UserFilter             string
	GroupsBaseDN           string
	CAFile                 string
	InsecureAllowPlaintext bool

	// NestedGroups resolves Active Directory nested group membership via
	// adMatchingRuleInChain instead of a flat groupOfNames search.
	NestedGroups bool
	// GroupCacheTTL caches a user's resolved groups for this long. Zero
	// disables the cache.
	GroupCacheTTL time.Duration
}

// ldapConn is the subset of *ldap.Conn that Authenticate needs; tests
// substitute a fake implementation instead of dialing a real directory.
type ldapConn interface {
	Bind(username, password string) error
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// groupCacheEntry is a user's resolved groups, valid until expiry.
type groupCacheEntry struct {
	groups []string
	expiry time.Time
}

// LDAP authenticates users against a directory with search-then-bind:
// bind as a read-only account, search for the user's DN, then bind as the
// user to check their password.
type LDAP struct {
	cfg       LDAPConfig
	tlsConfig *tls.Config
	// dial connects to the directory, trying every URL in cfg.urls() in
	// order; tests may replace it entirely to skip real dialing.
	dial func() (ldapConn, error)
	// dialURL connects to a single address; the failover loop behind dial
	// calls it once per URL. Tests override this to exercise failover
	// without replacing the loop itself.
	dialURL func(addr string) (ldapConn, error)
	// now is time.Now, overridable in tests for deterministic cache expiry.
	now func() time.Time

	groupCacheMu sync.Mutex
	groupCache   map[string]groupCacheEntry
}

// NewLDAP validates cfg and prepares an LDAP ready to authenticate. It
// refuses to start against a plaintext ldap:// URL unless StartTLS or
// InsecureAllowPlaintext is set.
func NewLDAP(cfg LDAPConfig) (*LDAP, error) {
	urls := cfg.URLs
	if len(urls) == 0 {
		urls = []string{cfg.URL}
	}
	for _, u := range urls {
		if strings.HasPrefix(u, "ldap://") && !cfg.StartTLS && !cfg.InsecureAllowPlaintext {
			return nil, fmt.Errorf("ldap: plaintext url requires start_tls or insecure_allow_plaintext")
		}
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

	l := &LDAP{cfg: cfg, tlsConfig: tlsConfig, now: time.Now}
	l.dialURL = l.dialOneReal
	l.dial = l.dialFailover
	return l, nil
}

// urls returns the ordered list of directory addresses to try.
func (l *LDAP) urls() []string {
	if len(l.cfg.URLs) > 0 {
		return l.cfg.URLs
	}
	return []string{l.cfg.URL}
}

func (l *LDAP) dialOneReal(addr string) (ldapConn, error) {
	conn, err := ldap.DialURL(addr, ldap.DialWithTLSConfig(l.tlsConfig))
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

// dialFailover tries every configured URL in order, returning the first
// successful connection. A rejected user bind is not a failover trigger —
// only Authenticate's dial/connect step goes through this loop.
func (l *LDAP) dialFailover() (ldapConn, error) {
	var errs []error
	for _, addr := range l.urls() {
		conn, err := l.dialURL(addr)
		if err == nil {
			return conn, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", addr, err))
	}
	return nil, fmt.Errorf("ldap: connect: %w", errors.Join(errs...))
}

func (l *LDAP) cachedGroups(key string) ([]string, bool) {
	l.groupCacheMu.Lock()
	defer l.groupCacheMu.Unlock()
	entry, ok := l.groupCache[key]
	if !ok {
		return nil, false
	}
	if l.now().After(entry.expiry) {
		delete(l.groupCache, key)
		return nil, false
	}
	return entry.groups, true
}

func (l *LDAP) storeGroups(key string, groups []string) {
	l.groupCacheMu.Lock()
	defer l.groupCacheMu.Unlock()
	if l.groupCache == nil {
		l.groupCache = make(map[string]groupCacheEntry)
	}
	l.groupCache[key] = groupCacheEntry{groups: groups, expiry: l.now().Add(l.cfg.GroupCacheTTL)}
}

// groupFilter builds the group-membership search filter for userDN: AD
// nested resolution when NestedGroups is set, otherwise a flat
// groupOfNames/member search (J1-03 behavior, unchanged for OpenLDAP).
func (l *LDAP) groupFilter(userDN string) string {
	escaped := ldap.EscapeFilter(userDN)
	if l.cfg.NestedGroups {
		return fmt.Sprintf("(&(objectClass=group)(member:%s:=%s))", adMatchingRuleInChain, escaped)
	}
	return fmt.Sprintf("(&(objectClass=groupOfNames)(member=%s))", escaped)
}

// findUser searches for username and returns its DN and mail attribute.
// conn must already be bound as an account with read access to BaseDN.
func (l *LDAP) findUser(conn ldapConn, username string) (userDN, email string, err error) {
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
		return "", "", fmt.Errorf("ldap: search: %w", err)
	}
	if len(sr.Entries) != 1 {
		return "", "", fmt.Errorf("ldap: user not found")
	}
	entry := sr.Entries[0]
	return entry.DN, entry.GetAttributeValue("mail"), nil
}

// searchGroups resolves userDN's flat group CNs, consulting and
// refreshing the group cache keyed by cacheKey. conn must already be
// bound as an account with read access to GroupsBaseDN.
func (l *LDAP) searchGroups(conn ldapConn, userDN, cacheKey string) ([]string, error) {
	if l.cfg.GroupCacheTTL > 0 {
		if groups, ok := l.cachedGroups(cacheKey); ok {
			return groups, nil
		}
	}
	groupsReq := ldap.NewSearchRequest(
		l.cfg.GroupsBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		l.groupFilter(userDN),
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
	if l.cfg.GroupCacheTTL > 0 {
		l.storeGroups(cacheKey, groups)
	}
	return groups, nil
}

// Lookup resolves username to an Identity (email, flat group CNs) via the
// read-only account, with no password check. Used by Kerberos (F2's
// counterpart for SPNEGO), which authenticates the ticket itself and has
// no password to bind with. A username absent from the directory fails:
// no groups, so no ACL match.
func (l *LDAP) Lookup(ctx context.Context, username string) (*Identity, error) {
	conn, err := l.dial()
	if err != nil {
		return nil, fmt.Errorf("ldap: connect: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(l.cfg.BindDN, l.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("ldap: readonly bind: %w", err)
	}
	userDN, email, err := l.findUser(conn, username)
	if err != nil {
		return nil, err
	}
	groups, err := l.searchGroups(conn, userDN, strings.ToLower(username))
	if err != nil {
		return nil, err
	}
	return &Identity{Subject: username, Email: email, Groups: groups}, nil
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
	userDN, email, err := l.findUser(conn, username)
	if err != nil {
		return nil, err
	}

	if err := conn.Bind(userDN, password); err != nil {
		return nil, fmt.Errorf("ldap: password rejected")
	}

	cacheKey := strings.ToLower(username)
	if l.cfg.GroupCacheTTL > 0 {
		if groups, ok := l.cachedGroups(cacheKey); ok {
			return &Identity{Subject: username, Email: email, Groups: groups}, nil
		}
	}

	// Re-bind as the read-only account: the user bind above replaced the
	// connection's authenticated identity, and group search must not run as
	// the user (who may lack read access to the groups tree).
	if err := conn.Bind(l.cfg.BindDN, l.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("ldap: readonly re-bind: %w", err)
	}
	groups, err := l.searchGroups(conn, userDN, cacheKey)
	if err != nil {
		return nil, err
	}

	return &Identity{Subject: username, Email: email, Groups: groups}, nil
}
