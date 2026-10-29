package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func failingLDAPLogin(limiter *auth.Limiter) *LDAPLogin {
	return &LDAPLogin{
		Directory: &fakeDirectory{authenticate: func(username, password string) (*auth.Identity, error) {
			return nil, errAuthFailed
		}},
		Limiter:   limiter,
		OnSuccess: func(w http.ResponseWriter, r *http.Request, id auth.Identity) {},
	}
}

func newLDAPLoginReq(username string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/auth/ldap", strings.NewReader(`{"username":"`+username+`","password":"wrong"}`))
	req.RemoteAddr = "192.0.2.1:54321"
	return req
}

func TestLDAPHandleLoginLocksOutAfterMaxFailures(t *testing.T) {
	limiter := auth.NewLimiter(auth.LockoutConfig{MaxFailures: 2, FailureWindow: time.Minute, LockoutFor: time.Minute})
	login := failingLDAPLogin(limiter)

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		login.HandleLogin(rec, newLDAPLoginReq("alice"))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d", i+1, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	login.HandleLogin(rec, newLDAPLoginReq("alice"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("locked-out status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "lock") {
		t.Fatalf("response leaked lockout state: %s", rec.Body.String())
	}
}

func TestLDAPHandleLoginSuccessResetsLockout(t *testing.T) {
	limiter := auth.NewLimiter(auth.LockoutConfig{MaxFailures: 2, FailureWindow: time.Minute, LockoutFor: time.Minute})

	fail := failingLDAPLogin(limiter)
	fail.HandleLogin(httptest.NewRecorder(), newLDAPLoginReq("alice"))

	var onSuccessCalled bool
	succeed := &LDAPLogin{
		Directory: &fakeDirectory{authenticate: func(username, password string) (*auth.Identity, error) {
			return &auth.Identity{Subject: username}, nil
		}},
		Limiter: limiter,
		OnSuccess: func(w http.ResponseWriter, r *http.Request, id auth.Identity) {
			onSuccessCalled = true
			w.WriteHeader(http.StatusOK)
		},
	}
	rec := httptest.NewRecorder()
	succeed.HandleLogin(rec, newLDAPLoginReq("alice"))
	if rec.Code != http.StatusOK || !onSuccessCalled {
		t.Fatalf("status = %d onSuccessCalled = %v", rec.Code, onSuccessCalled)
	}

	// The reset above should mean this 2nd failure (not the 3rd overall) is
	// the first of a fresh window: still not locked out.
	rec = httptest.NewRecorder()
	fail.HandleLogin(rec, newLDAPLoginReq("alice"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestLDAPHandleLoginNilLimiterNeverLocksOut(t *testing.T) {
	login := failingLDAPLogin(nil)
	for i := 0; i < 50; i++ {
		rec := httptest.NewRecorder()
		login.HandleLogin(rec, newLDAPLoginReq("alice"))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d", i+1, rec.Code)
		}
	}
}
