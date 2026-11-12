package acl

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestESResolverResolvesAliasToIndices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "ApiKey secret-key" {
			t.Fatalf("missing/wrong auth header: %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/_resolve/index/public" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"indices": []map[string]string{},
			"aliases": []map[string]any{
				{"name": "public", "indices": []string{"secret"}},
			},
		})
	}))
	defer srv.Close()

	r := NewESResolver(srv.URL, "secret-key")
	got, err := r.Resolve(context.Background(), []string{"public"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "secret" {
		t.Fatalf("resolved = %v", got)
	}
}

func TestESResolverRejectsNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	r := NewESResolver(srv.URL, "secret-key")
	if _, err := r.Resolve(context.Background(), []string{"missing"}); err == nil {
		t.Fatal("expected error for non-200 status")
	}
}
