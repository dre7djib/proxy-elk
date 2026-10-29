package auth

import (
	"context"
	"fmt"
	"strings"
	"testing"

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

func TestAuthenticateEscapesInjectionAttempt(t *testing.T) {
	var capturedFilter string
	userDN := "uid=alice,ou=people,dc=example,dc=org"
	conn := &fakeConn{userDN: userDN, userPassword: "pw"}
	l := newTestLDAP(t, conn)
	l.dial = func() (ldapConn, error) {
		return &filterCapturingConn{fakeConn: conn, captured: &capturedFilter}, nil
	}

	malicious := "*)(uid=*"
	if _, err := l.Authenticate(context.Background(), malicious, "pw"); err == nil {
		t.Fatal("expected error: injected filter matches nothing in the fake directory")
	}
	if strings.Contains(capturedFilter, "*)(uid=*") {
		t.Fatalf("filter was not escaped: %s", capturedFilter)
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
