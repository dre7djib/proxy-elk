package esql

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestEnrichClientSourceIndices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_enrich/policy/sp05-owners-a-policy" {
			t.Fatalf("path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "ApiKey secret" {
			t.Fatalf("auth %q", r.Header.Get("Authorization"))
		}
		w.Write([]byte(`{"policies":[{"config":{"match":{"name":"sp05-owners-a-policy","indices":["equipe-a-sp05-owners"],"match_field":"host","enrich_fields":["owner"]}}}]}`))
	}))
	t.Cleanup(srv.Close)

	c := &EnrichClient{URL: srv.URL, APIKey: "secret", HTTPClient: srv.Client()}
	got, err := c.SourceIndices(context.Background(), "sp05-owners-a-policy")
	if err != nil || !reflect.DeepEqual(got, []string{"equipe-a-sp05-owners"}) {
		t.Fatalf("got %v err %v", got, err)
	}
}

func TestEnrichClientStringIndices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"policies":[{"config":{"match":{"indices":"equipe-a-owners","match_field":"host","enrich_fields":["owner"]}}}]}`))
	}))
	t.Cleanup(srv.Close)
	c := &EnrichClient{URL: srv.URL}
	got, err := c.SourceIndices(context.Background(), "p")
	if err != nil || !reflect.DeepEqual(got, []string{"equipe-a-owners"}) {
		t.Fatalf("got %v err %v", got, err)
	}
}

func TestEnrichClientMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"policies":[]}`))
	}))
	t.Cleanup(srv.Close)
	c := &EnrichClient{URL: srv.URL}
	if _, err := c.SourceIndices(context.Background(), "missing"); err == nil {
		t.Fatal("expected error")
	}
}
