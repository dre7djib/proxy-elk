package es

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"proxy/internal/acl"
	"proxy/internal/auth"
)

var errAuthFailed = errors.New("authentication failed")

// fakeDirectory stubs auth.PasswordAuthenticator via an injected function,
// so these tests never touch a real directory.
type fakeDirectory struct {
	authenticate func(username, password string) (*auth.Identity, error)
}

func (f *fakeDirectory) Authenticate(ctx context.Context, username, password string) (*auth.Identity, error) {
	return f.authenticate(username, password)
}

// echoResolver resolves every name to itself: these tests exercise
// Decide, not alias resolution (covered by esresolver_test.go).
type echoResolver struct{}

func (echoResolver) Resolve(ctx context.Context, names []string) ([]string, error) {
	return names, nil
}

func testPolicy(t *testing.T) *acl.Policy {
	t.Helper()
	p, err := acl.Parse([]acl.Rule{
		{Name: "equipe-a-read", Groups: []string{"equipe-a-viewer"}, Indices: []string{"equipe-a-*"}, Actions: []string{"read"}},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newTestRelay(t *testing.T, upstream http.HandlerFunc) (http.Handler, *bool) {
	t.Helper()
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		upstream(w, r)
	}))
	t.Cleanup(srv.Close)
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(t)
	relay := NewRelay(Config{
		Target: target,
		LDAP: &fakeDirectory{authenticate: func(username, password string) (*auth.Identity, error) {
			if username == "alice" && password == "goodpass" {
				return &auth.Identity{Subject: "alice", Groups: []string{"equipe-a-viewer"}}, nil
			}
			return nil, errAuthFailed
		}},
		Policy:         func() *acl.Policy { return policy },
		Resolver:       echoResolver{},
		RunAsUser:      "proxy_service",
		RunAsPassword:  "runas-secret",
		ShadowPassword: "shadow-secret",
		Passthrough:    map[string]bool{"kibana_system": true},
	})
	return relay, &called
}

func basicHeader(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

func TestRelayLDAPUserRunAsNeverLeaksPassword(t *testing.T) {
	var gotAuth, gotRunAs string
	relay, called := newTestRelay(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotRunAs = r.Header.Get("es-security-runas-user")
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/equipe-a-sample/_search", nil)
	req.Header.Set("Authorization", basicHeader("alice", "goodpass"))
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !*called {
		t.Fatal("upstream was never called")
	}
	if gotAuth != basicHeader("proxy_service", "runas-secret") {
		t.Fatalf("upstream Authorization = %q, want proxy_service/runas-secret", gotAuth)
	}
	if gotRunAs != "alice" {
		t.Fatalf("es-security-runas-user = %q, want alice", gotRunAs)
	}
	if strings.Contains(gotAuth, "goodpass") {
		t.Fatal("alice's password leaked upstream")
	}
}

func TestRelayWrongPasswordDenied(t *testing.T) {
	relay, called := newTestRelay(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/equipe-a-sample/_search", nil)
	req.Header.Set("Authorization", basicHeader("alice", "wrongpass"))
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if *called {
		t.Fatal("upstream was called")
	}
}

func TestRelayActivateSubstitutesPasswordAfterLDAPSuccess(t *testing.T) {
	var gotBody map[string]any
	relay, called := newTestRelay(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusOK)
	})

	body := `{"grant_type":"password","username":"alice","password":"goodpass"}`
	req := httptest.NewRequest(http.MethodPost, "/_security/profile/_activate", strings.NewReader(body))
	req.Header.Set("Authorization", basicHeader("kibana_system", "kibana-pass"))
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !*called {
		t.Fatal("upstream was never called")
	}
	if gotBody["password"] != "shadow-secret" {
		t.Fatalf("upstream body password = %v, want shadow-secret", gotBody["password"])
	}
}

// TestRelayActivateAcceptsShadowPasswordWithoutLDAPBind covers the
// Kerberos path: its /auth/kibana SSO has no LDAP password, so it logs
// into Kibana with ShadowPassword directly, and that's what arrives here
// in the activate body. No LDAP directory call should happen at all.
// TestRelayBasicAuthWithShadowPasswordUsesLookupNotBind covers a real bug
// found running the demo end-to-end: Kibana's basic provider re-validates
// login credentials with GET /_security/_authenticate using plain Basic
// auth (not just POST /_security/profile/_activate), so the Kerberos SSO
// path — whose only "password" is ShadowPassword — hit the normal LDAP
// bind branch and got rejected. Basic auth carrying the shadow password
// must resolve via Lookup instead.
func TestRelayBasicAuthWithShadowPasswordUsesLookupNotBind(t *testing.T) {
	var ldapCalled, lookupCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(t)
	relay := NewRelay(Config{
		Target: target,
		LDAP: &fakeDirectory{authenticate: func(username, password string) (*auth.Identity, error) {
			ldapCalled = true
			return nil, errAuthFailed
		}},
		Lookup: func(ctx context.Context, username string) (*auth.Identity, error) {
			lookupCalled = true
			return &auth.Identity{Subject: username, Groups: []string{"equipe-a-viewer"}}, nil
		},
		Policy:         func() *acl.Policy { return policy },
		Resolver:       echoResolver{},
		RunAsUser:      "proxy_service",
		RunAsPassword:  "runas-secret",
		ShadowPassword: "shadow-secret",
		Passthrough:    map[string]bool{"kibana_system": true},
	})

	req := httptest.NewRequest(http.MethodGet, "/equipe-a-sample/_search", nil)
	req.Header.Set("Authorization", basicHeader("alice", "shadow-secret"))
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if ldapCalled {
		t.Fatal("LDAP bind must not be attempted with the shadow password")
	}
	if !lookupCalled {
		t.Fatal("Lookup was not called")
	}
}

func TestRelayActivateAcceptsShadowPasswordWithoutLDAPBind(t *testing.T) {
	var gotBody map[string]any
	var ldapCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(t)
	relay := NewRelay(Config{
		Target: target,
		LDAP: &fakeDirectory{authenticate: func(username, password string) (*auth.Identity, error) {
			ldapCalled = true
			return nil, errAuthFailed
		}},
		Policy:         func() *acl.Policy { return policy },
		Resolver:       echoResolver{},
		RunAsUser:      "proxy_service",
		RunAsPassword:  "runas-secret",
		ShadowPassword: "shadow-secret",
		Passthrough:    map[string]bool{"kibana_system": true},
	})

	body := `{"grant_type":"password","username":"alice","password":"shadow-secret"}`
	req := httptest.NewRequest(http.MethodPost, "/_security/profile/_activate", strings.NewReader(body))
	req.Header.Set("Authorization", basicHeader("kibana_system", "kibana-pass"))
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if ldapCalled {
		t.Fatal("LDAP must not be called when the body already carries the shadow password")
	}
	if gotBody["password"] != "shadow-secret" {
		t.Fatalf("upstream body password = %v, want shadow-secret", gotBody["password"])
	}
}

func TestRelayActivateDeniedOnBadLDAPPassword(t *testing.T) {
	relay, called := newTestRelay(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must not be called")
	})

	body := `{"grant_type":"password","username":"alice","password":"wrongpass"}`
	req := httptest.NewRequest(http.MethodPost, "/_security/profile/_activate", strings.NewReader(body))
	req.Header.Set("Authorization", basicHeader("kibana_system", "kibana-pass"))
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if *called {
		t.Fatal("upstream was called")
	}
}

func newTestRelayWithKerberos(t *testing.T, kerberos *auth.Kerberos, upstream http.HandlerFunc) (http.Handler, *bool) {
	t.Helper()
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		upstream(w, r)
	}))
	t.Cleanup(srv.Close)
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(t)
	relay := NewRelay(Config{
		Target:        target,
		Kerberos:      kerberos,
		Policy:        func() *acl.Policy { return policy },
		Resolver:      echoResolver{},
		RunAsUser:     "proxy_service",
		RunAsPassword: "runas-secret",
		Passthrough:   map[string]bool{"kibana_system": true},
	})
	return relay, &called
}

func TestRelayNegotiateAuthenticatesThenRunAs(t *testing.T) {
	k := auth.NewKerberosForTest("EXAMPLE.ORG")
	k.Accept = func(token string) (string, string, error) { return "alice", "EXAMPLE.ORG", nil }
	k.Lookup = func(ctx context.Context, username string) (*auth.Identity, error) {
		return &auth.Identity{Subject: username, Groups: []string{"equipe-a-viewer"}}, nil
	}

	var gotAuth, gotRunAs string
	relay, called := newTestRelayWithKerberos(t, k, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotRunAs = r.Header.Get("es-security-runas-user")
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/equipe-a-sample/_search", nil)
	req.Header.Set("Authorization", "Negotiate dG9rZW4=")
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !*called {
		t.Fatal("upstream was never called")
	}
	if gotAuth != basicHeader("proxy_service", "runas-secret") {
		t.Fatalf("upstream Authorization = %q", gotAuth)
	}
	if gotRunAs != "alice" {
		t.Fatalf("es-security-runas-user = %q, want alice", gotRunAs)
	}
}

func TestRelayBasicLDAPTakesPriorityOverNegotiate(t *testing.T) {
	k := auth.NewKerberosForTest("EXAMPLE.ORG")
	k.Accept = func(token string) (string, string, error) {
		t.Fatal("kerberos must not be consulted when Basic auth is present")
		return "", "", nil
	}

	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(t)
	relay := NewRelay(Config{
		Target: target,
		LDAP: &fakeDirectory{authenticate: func(username, password string) (*auth.Identity, error) {
			return &auth.Identity{Subject: "alice", Groups: []string{"equipe-a-viewer"}}, nil
		}},
		Kerberos:      k,
		Policy:        func() *acl.Policy { return policy },
		Resolver:      echoResolver{},
		RunAsUser:     "proxy_service",
		RunAsPassword: "runas-secret",
		Passthrough:   map[string]bool{"kibana_system": true},
	})

	req := httptest.NewRequest(http.MethodGet, "/equipe-a-sample/_search", nil)
	req.Header.Set("Authorization", basicHeader("alice", "goodpass"))
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !called {
		t.Fatal("upstream was never called")
	}
}

func TestRelayNoAuthAddsNegotiateHeaderOnlyWhenKerberosConfigured(t *testing.T) {
	k := auth.NewKerberosForTest("EXAMPLE.ORG")
	relay, _ := newTestRelayWithKerberos(t, k, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must not be called")
	})

	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/equipe-a-sample/_search", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "Negotiate" {
		t.Fatalf("WWW-Authenticate = %q, want Negotiate", got)
	}
}

func TestRelayNoAuthNoNegotiateHeaderWithoutKerberos(t *testing.T) {
	relay, _ := newTestRelay(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must not be called")
	})

	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/equipe-a-sample/_search", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("WWW-Authenticate = %q, want empty", got)
	}
}

func TestRelayIndexOutsideRuleDenied(t *testing.T) {
	relay, called := newTestRelay(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/equipe-b-sample/_search", nil)
	req.Header.Set("Authorization", basicHeader("alice", "goodpass"))
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if *called {
		t.Fatal("upstream was called")
	}
}

func TestRelayKibanaSystemPassesThroughUnchanged(t *testing.T) {
	var gotAuth string
	relay, called := newTestRelay(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/.kibana_task_manager/_doc/1", nil)
	req.Header.Set("Authorization", basicHeader("kibana_system", "kibana-pass"))
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !*called {
		t.Fatal("upstream was never called")
	}
	if gotAuth != basicHeader("kibana_system", "kibana-pass") {
		t.Fatalf("Authorization = %q, want unchanged kibana_system credentials", gotAuth)
	}
}

func TestRelayBulkWriteFromUserDenied(t *testing.T) {
	relay, called := newTestRelay(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must not be called")
	})

	req := httptest.NewRequest(http.MethodPost, "/_bulk", strings.NewReader(`{}`))
	req.Header.Set("Authorization", basicHeader("alice", "goodpass"))
	rec := httptest.NewRecorder()
	relay.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if *called {
		t.Fatal("upstream was called")
	}
}
