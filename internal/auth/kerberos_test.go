package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testKerberos(t *testing.T, realm string, accept func(token string) (string, string, error), lookup func(ctx context.Context, username string) (*Identity, error)) *Kerberos {
	t.Helper()
	k := NewKerberosForTest(realm)
	k.Accept, k.Lookup = accept, lookup
	return k
}

func TestKerberosMiddlewareNoTokenChallenges401Negotiate(t *testing.T) {
	k := testKerberos(t, "EXAMPLE.ORG", nil, nil)
	rec := httptest.NewRecorder()
	k.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler must not run without a ticket")
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/kibana", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "Negotiate" {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

func TestKerberosMiddlewareRejectedTokenIs401(t *testing.T) {
	k := testKerberos(t, "EXAMPLE.ORG", func(token string) (string, string, error) {
		return "", "", fmt.Errorf("kerberos: ticket rejected")
	}, nil)
	req := httptest.NewRequest(http.MethodGet, "/auth/kibana", nil)
	req.Header.Set("Authorization", "Negotiate garbage")
	rec := httptest.NewRecorder()
	k.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler must not run with a rejected ticket")
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "Negotiate" {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

func TestKerberosAuthenticateWrongRealmRejected(t *testing.T) {
	k := testKerberos(t, "EXAMPLE.ORG", func(token string) (string, string, error) {
		return "alice", "OTHER.ORG", nil
	}, func(ctx context.Context, username string) (*Identity, error) {
		t.Fatal("Lookup must not run for a wrong realm")
		return nil, nil
	})
	req := httptest.NewRequest(http.MethodGet, "/auth/kibana", nil)
	req.Header.Set("Authorization", "Negotiate dG9rZW4=")
	if _, err := k.Authenticate(req); err == nil {
		t.Fatal("expected an error for a mismatched realm")
	}
}

func TestKerberosAuthenticateLooksUpGroups(t *testing.T) {
	k := testKerberos(t, "EXAMPLE.ORG", func(token string) (string, string, error) {
		return "alice", "EXAMPLE.ORG", nil
	}, func(ctx context.Context, username string) (*Identity, error) {
		if username != "alice" {
			t.Fatalf("Lookup username = %q", username)
		}
		return &Identity{Subject: username, Groups: []string{"equipe-a-viewer"}}, nil
	})
	req := httptest.NewRequest(http.MethodGet, "/auth/kibana", nil)
	req.Header.Set("Authorization", "Negotiate dG9rZW4=")
	id, err := k.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "alice" || len(id.Groups) != 1 || id.Groups[0] != "equipe-a-viewer" {
		t.Fatalf("identity = %+v", id)
	}
}

func TestKerberosAuthenticateUserAbsentFromDirectoryFails(t *testing.T) {
	k := testKerberos(t, "EXAMPLE.ORG", func(token string) (string, string, error) {
		return "ghost", "EXAMPLE.ORG", nil
	}, func(ctx context.Context, username string) (*Identity, error) {
		return nil, fmt.Errorf("ldap: user not found")
	})
	req := httptest.NewRequest(http.MethodGet, "/auth/kibana", nil)
	req.Header.Set("Authorization", "Negotiate dG9rZW4=")
	if _, err := k.Authenticate(req); err == nil {
		t.Fatal("expected an error for a user absent from the directory")
	}
}
