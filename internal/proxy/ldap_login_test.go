package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proxy/internal/auth"
)

// fakeDirectory stubs auth.LDAP's Authenticate behavior via an injected
// function, so the handler test never touches a real directory.
type fakeDirectory struct {
	authenticate func(username, password string) (*auth.Identity, error)
}

func (f *fakeDirectory) Authenticate(ctx context.Context, username, password string) (*auth.Identity, error) {
	return f.authenticate(username, password)
}

var errAuthFailed = errors.New("authentication failed")

func TestLDAPHandleLoginSuccess(t *testing.T) {
	var gotIdentity auth.Identity
	var onSuccessCalled bool
	login := &LDAPLogin{
		Directory: &fakeDirectory{authenticate: func(username, password string) (*auth.Identity, error) {
			return &auth.Identity{Subject: username, Groups: []string{"team-viewer"}}, nil
		}},
		OnSuccess: func(w http.ResponseWriter, r *http.Request, id auth.Identity) {
			onSuccessCalled = true
			gotIdentity = id
			w.WriteHeader(http.StatusOK)
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/ldap", strings.NewReader(`{"username":"alice","password":"secret"}`))
	rec := httptest.NewRecorder()
	login.HandleLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !onSuccessCalled || gotIdentity.Subject != "alice" {
		t.Fatalf("identity = %+v", gotIdentity)
	}
}

func TestLDAPHandleLoginRejectsBadCredentials(t *testing.T) {
	login := &LDAPLogin{
		Directory: &fakeDirectory{authenticate: func(username, password string) (*auth.Identity, error) {
			return nil, errAuthFailed
		}},
		OnSuccess: func(w http.ResponseWriter, r *http.Request, id auth.Identity) {
			t.Fatal("OnSuccess must not be called")
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/ldap", strings.NewReader(`{"username":"alice","password":"wrong"}`))
	rec := httptest.NewRecorder()
	login.HandleLogin(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "ldap") {
		t.Fatalf("response leaked directory detail: %s", rec.Body.String())
	}
}

func TestLDAPHandleLoginRejectsMalformedBody(t *testing.T) {
	login := &LDAPLogin{
		Directory: &fakeDirectory{authenticate: func(username, password string) (*auth.Identity, error) {
			t.Fatal("Authenticate must not be called for a malformed body")
			return nil, nil
		}},
		OnSuccess: func(w http.ResponseWriter, r *http.Request, id auth.Identity) {
			t.Fatal("OnSuccess must not be called")
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/ldap", strings.NewReader(`not json`))
	rec := httptest.NewRecorder()
	login.HandleLogin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestLDAPHandleLoginRejectsEmptyUsername(t *testing.T) {
	login := &LDAPLogin{
		Directory: &fakeDirectory{authenticate: func(username, password string) (*auth.Identity, error) {
			t.Fatal("Authenticate must not be called for an empty username")
			return nil, nil
		}},
		OnSuccess: func(w http.ResponseWriter, r *http.Request, id auth.Identity) {
			t.Fatal("OnSuccess must not be called")
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/ldap", strings.NewReader(`{"username":"","password":"x"}`))
	rec := httptest.NewRecorder()
	login.HandleLogin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}
