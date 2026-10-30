package auth

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestNewLDAPRejectsPlaintext(t *testing.T) {
	_, err := NewLDAP(LDAPConfig{URL: "ldap://directory.example:389"})
	if err == nil || !strings.Contains(err.Error(), "plaintext") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewLDAPAllowsStartTLS(t *testing.T) {
	if _, err := NewLDAP(LDAPConfig{URL: "ldap://directory.example:389", StartTLS: true}); err != nil {
		t.Fatal(err)
	}
}

func TestNewLDAPAllowsExplicitPlaintext(t *testing.T) {
	if _, err := NewLDAP(LDAPConfig{URL: "ldap://directory.example:389", InsecureAllowPlaintext: true}); err != nil {
		t.Fatal(err)
	}
}

func TestNewLDAPAllowsLDAPS(t *testing.T) {
	if _, err := NewLDAP(LDAPConfig{URL: "ldaps://directory.example:636"}); err != nil {
		t.Fatal(err)
	}
}

// fakeConn stubs the subset of *ldap.Conn Authenticate uses, so tests never
// dial a real directory.
type fakeConn struct {
	closed bool

	readonlyDN, readonlyPassword string
	userDN, userPassword         string

	userEntries  []*ldap.Entry
	groupEntries []*ldap.Entry
	searchErr    error

	binds []string // "dn:password" for every successful Bind call, in order
}

func (f *fakeConn) Bind(dn, password string) error {
	switch {
	case dn == f.readonlyDN && password == f.readonlyPassword:
		f.binds = append(f.binds, dn+":"+password)
		return nil
	case dn == f.userDN && password == f.userPassword:
		f.binds = append(f.binds, dn+":"+password)
		return nil
	default:
		return fmt.Errorf("bind rejected for %s", dn)
	}
}

func (f *fakeConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	if req.BaseDN == groupsBaseDN {
		return &ldap.SearchResult{Entries: f.groupEntries}, nil
	}
	return &ldap.SearchResult{Entries: f.userEntries}, nil
}

func (f *fakeConn) Close() error {
	f.closed = true
	return nil
}

const (
	readonlyDN   = "cn=readonly,dc=example,dc=org"
	baseDN       = "ou=people,dc=example,dc=org"
	groupsBaseDN = "ou=groups,dc=example,dc=org"
)

func newTestLDAP(t *testing.T, conn *fakeConn) *LDAP {
	t.Helper()
	l, err := NewLDAP(LDAPConfig{
		URL:          "ldaps://directory.example:636",
		BindDN:       readonlyDN,
		BindPassword: "readonly-secret",
		BaseDN:       baseDN,
		UserFilter:   "(uid=%s)",
		GroupsBaseDN: groupsBaseDN,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.readonlyDN = readonlyDN
	conn.readonlyPassword = "readonly-secret"
	l.dial = func() (ldapConn, error) { return conn, nil }
	return l
}

func TestAuthenticateSuccess(t *testing.T) {
	userDN := "uid=alice,ou=people,dc=example,dc=org"
	conn := &fakeConn{
		userDN:       userDN,
		userPassword: "alice-pw",
		userEntries:  []*ldap.Entry{ldap.NewEntry(userDN, map[string][]string{"mail": {"alice@example.com"}})},
		groupEntries: []*ldap.Entry{
			ldap.NewEntry("cn=team-payments-viewer,"+groupsBaseDN, map[string][]string{"cn": {"team-payments-viewer"}}),
		},
	}
	l := newTestLDAP(t, conn)

	id, err := l.Authenticate(context.Background(), "alice", "alice-pw")
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "alice" || id.Email != "alice@example.com" {
		t.Fatalf("identity = %+v", id)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "team-payments-viewer" {
		t.Fatalf("groups = %v", id.Groups)
	}
	if !conn.closed {
		t.Fatal("connection not closed")
	}
	// Readonly bind, then user bind, then readonly re-bind.
	want := []string{readonlyDN + ":readonly-secret", userDN + ":alice-pw", readonlyDN + ":readonly-secret"}
	if len(conn.binds) != len(want) {
		t.Fatalf("binds = %v", conn.binds)
	}
	for i := range want {
		if conn.binds[i] != want[i] {
			t.Fatalf("binds = %v", conn.binds)
		}
	}
}

func TestAuthenticateEmptyPasswordNeverDials(t *testing.T) {
	conn := &fakeConn{}
	l := newTestLDAP(t, conn)
	l.dial = func() (ldapConn, error) {
		t.Fatal("dial must not be called for an empty password")
		return nil, nil
	}

	if _, err := l.Authenticate(context.Background(), "alice", ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestAuthenticateUserNotFound(t *testing.T) {
	conn := &fakeConn{userEntries: nil}
	l := newTestLDAP(t, conn)

	if _, err := l.Authenticate(context.Background(), "ghost", "whatever"); err == nil {
		t.Fatal("expected error for missing user")
	}
}

func TestAuthenticateAmbiguousMatch(t *testing.T) {
	conn := &fakeConn{userEntries: []*ldap.Entry{
		ldap.NewEntry("uid=a,"+baseDN, nil),
		ldap.NewEntry("uid=b,"+baseDN, nil),
	}}
	l := newTestLDAP(t, conn)

	if _, err := l.Authenticate(context.Background(), "a", "whatever"); err == nil {
		t.Fatal("expected error for ambiguous match")
	}
}

func TestAuthenticateWrongPassword(t *testing.T) {
	userDN := "uid=alice,ou=people,dc=example,dc=org"
	conn := &fakeConn{
		userDN:       userDN,
		userPassword: "alice-pw",
		userEntries:  []*ldap.Entry{ldap.NewEntry(userDN, nil)},
	}
	l := newTestLDAP(t, conn)

	if _, err := l.Authenticate(context.Background(), "alice", "wrong-password"); err == nil {
		t.Fatal("expected error for wrong password")
	}
}

// TestAuthenticateInjectionBattery (F7): every one of these usernames must
// fail authentication, and the filter the directory sees must carry the
// escaped form, never the raw metacharacters.
func TestAuthenticateInjectionBattery(t *testing.T) {
	cases := []struct {
		name, username string
	}{
		{"wildcard filter widening", "*)(uid=*"},
		{"admin OR injection", "admin)(|(uid=*"},
		{"bare wildcard", "*"},
		{"bare backslash", "\\"},
		{"embedded null byte", "alice\x00"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var capturedFilter string
			userDN := "uid=alice,ou=people,dc=example,dc=org"
			conn := &fakeConn{userDN: userDN, userPassword: "pw"}
			l := newTestLDAP(t, conn)
			l.dial = func() (ldapConn, error) {
				return &filterCapturingConn{fakeConn: conn, captured: &capturedFilter}, nil
			}

			if _, err := l.Authenticate(context.Background(), c.username, "pw"); err == nil {
				t.Fatal("expected error: injected filter matches nothing in the fake directory")
			}
			want := fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(c.username))
			if capturedFilter != want {
				t.Fatalf("filter = %q, want escaped form %q", capturedFilter, want)
			}
		})
	}
}

// filterCapturingConn records the filter string passed to the first Search
// call, to verify EscapeFilter neutralized a malicious username.
type filterCapturingConn struct {
	*fakeConn
	captured *string
}

func (f *filterCapturingConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if *f.captured == "" {
		*f.captured = req.Filter
	}
	return f.fakeConn.Search(req)
}

// groupSearchConn wraps fakeConn to record the filter and call count of
// every groups-tree search, leaving the user-tree search untouched.
type groupSearchConn struct {
	*fakeConn
	groupFilters []string
}

func (f *groupSearchConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if req.BaseDN == groupsBaseDN {
		f.groupFilters = append(f.groupFilters, req.Filter)
	}
	return f.fakeConn.Search(req)
}

func newTestLDAPWithConfig(t *testing.T, cfg LDAPConfig, conn *fakeConn) *LDAP {
	t.Helper()
	cfg.URL = "ldaps://directory.example:636"
	cfg.BindDN = readonlyDN
	cfg.BindPassword = "readonly-secret"
	cfg.BaseDN = baseDN
	cfg.UserFilter = "(uid=%s)"
	cfg.GroupsBaseDN = groupsBaseDN
	l, err := NewLDAP(cfg)
	if err != nil {
		t.Fatal(err)
	}
	conn.readonlyDN = readonlyDN
	conn.readonlyPassword = "readonly-secret"
	return l
}

func TestAuthenticateFlatGroupFilterByDefault(t *testing.T) {
	userDN := "uid=alice," + baseDN
	inner := &fakeConn{userDN: userDN, userPassword: "pw", userEntries: []*ldap.Entry{ldap.NewEntry(userDN, nil)}}
	spy := &groupSearchConn{fakeConn: inner}
	l := newTestLDAPWithConfig(t, LDAPConfig{}, inner)
	l.dial = func() (ldapConn, error) { return spy, nil }

	if _, err := l.Authenticate(context.Background(), "alice", "pw"); err != nil {
		t.Fatal(err)
	}
	if len(spy.groupFilters) != 1 || !strings.Contains(spy.groupFilters[0], "groupOfNames") {
		t.Fatalf("group filters = %v", spy.groupFilters)
	}
}

func TestAuthenticateNestedGroupFilter(t *testing.T) {
	userDN := "uid=alice," + baseDN
	inner := &fakeConn{userDN: userDN, userPassword: "pw", userEntries: []*ldap.Entry{ldap.NewEntry(userDN, nil)}}
	spy := &groupSearchConn{fakeConn: inner}
	l := newTestLDAPWithConfig(t, LDAPConfig{NestedGroups: true}, inner)
	l.dial = func() (ldapConn, error) { return spy, nil }

	if _, err := l.Authenticate(context.Background(), "alice", "pw"); err != nil {
		t.Fatal(err)
	}
	if len(spy.groupFilters) != 1 || !strings.Contains(spy.groupFilters[0], adMatchingRuleInChain) {
		t.Fatalf("group filters = %v", spy.groupFilters)
	}
}

func TestAuthenticateGroupCacheSkipsRepeatSearch(t *testing.T) {
	userDN := "uid=alice," + baseDN
	inner := &fakeConn{
		userDN: userDN, userPassword: "pw",
		userEntries:  []*ldap.Entry{ldap.NewEntry(userDN, nil)},
		groupEntries: []*ldap.Entry{ldap.NewEntry("cn=g1,"+groupsBaseDN, map[string][]string{"cn": {"g1"}})},
	}
	spy := &groupSearchConn{fakeConn: inner}
	l := newTestLDAPWithConfig(t, LDAPConfig{GroupCacheTTL: time.Minute}, inner)
	l.dial = func() (ldapConn, error) { return spy, nil }
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return clock }

	first, err := l.Authenticate(context.Background(), "alice", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if len(spy.groupFilters) != 1 {
		t.Fatalf("expected 1 search, got %d", len(spy.groupFilters))
	}

	second, err := l.Authenticate(context.Background(), "alice", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if len(spy.groupFilters) != 1 {
		t.Fatalf("expected cache hit (still 1 search), got %d", len(spy.groupFilters))
	}
	if len(second.Groups) != 1 || second.Groups[0] != first.Groups[0] {
		t.Fatalf("cached groups = %v want %v", second.Groups, first.Groups)
	}

	clock = clock.Add(2 * time.Minute)
	if _, err := l.Authenticate(context.Background(), "alice", "pw"); err != nil {
		t.Fatal(err)
	}
	if len(spy.groupFilters) != 2 {
		t.Fatalf("expected a fresh search after TTL expiry, got %d", len(spy.groupFilters))
	}
}

// failoverConn is a minimal ldapConn for the failover test: no real
// directory behavior needed, Authenticate itself isn't exercised, only
// LDAP.dial (the failover loop) via dialURL.
type failoverConn struct{ addr string }

func (c *failoverConn) Bind(string, string) error { return nil }
func (c *failoverConn) Search(*ldap.SearchRequest) (*ldap.SearchResult, error) {
	return &ldap.SearchResult{}, nil
}
func (c *failoverConn) Close() error { return nil }

func TestDialFailoverTriesNextURLOnFailure(t *testing.T) {
	l, err := NewLDAP(LDAPConfig{URLs: []string{"ldaps://dc1.example:636", "ldaps://dc2.example:636"}})
	if err != nil {
		t.Fatal(err)
	}
	var tried []string
	l.dialURL = func(addr string) (ldapConn, error) {
		tried = append(tried, addr)
		if addr == "ldaps://dc1.example:636" {
			return nil, fmt.Errorf("connection refused")
		}
		return &failoverConn{addr: addr}, nil
	}

	conn, err := l.dial()
	if err != nil {
		t.Fatal(err)
	}
	if got := conn.(*failoverConn).addr; got != "ldaps://dc2.example:636" {
		t.Fatalf("connected to %q, want dc2", got)
	}
	if len(tried) != 2 {
		t.Fatalf("tried = %v", tried)
	}
}

func TestDialFailoverFailsWhenAllURLsFail(t *testing.T) {
	l, err := NewLDAP(LDAPConfig{URLs: []string{"ldaps://dc1.example:636", "ldaps://dc2.example:636"}})
	if err != nil {
		t.Fatal(err)
	}
	l.dialURL = func(addr string) (ldapConn, error) { return nil, fmt.Errorf("connection refused") }

	if _, err := l.dial(); err == nil {
		t.Fatal("expected error when every URL fails")
	}
}
