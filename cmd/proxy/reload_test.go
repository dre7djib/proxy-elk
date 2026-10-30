package main

import (
	"bytes"
	"os"
	"testing"

	"proxy/internal/acl"
	"proxy/internal/auth"
)

func TestPolicyStoreReloadLoadsPolicy(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	path := writeTestConfig(`
listen: ":0"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
` + minimalACL)

	store := newPolicyStore()
	if store.Current() != nil {
		t.Fatal("expected no policy before the first Reload")
	}
	var stderr bytes.Buffer
	if err := store.Reload(path, &stderr); err != nil {
		t.Fatal(err)
	}
	if store.Current() == nil {
		t.Fatal("expected a policy after a successful Reload")
	}
}

func TestPolicyStoreReloadKeepsOldPolicyOnInvalidFile(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	path := writeTestConfig(`
listen: ":0"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
` + minimalACL)

	store := newPolicyStore()
	var stderr bytes.Buffer
	if err := store.Reload(path, &stderr); err != nil {
		t.Fatal(err)
	}
	first := store.Current()

	// Overwrite with a config that has no ACL rules at all — invalid.
	if err := os.WriteFile(path, []byte(`
listen: ":0"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	stderr.Reset()
	if err := store.Reload(path, &stderr); err == nil {
		t.Fatal("expected Reload to fail on the invalid file")
	}
	if stderr.Len() == 0 {
		t.Fatal("expected one stderr line on reload failure")
	}
	if store.Current() != first {
		t.Fatal("Reload must keep the previous policy on failure")
	}
}

func TestPolicyStoreReloadPicksUpNewRules(t *testing.T) {
	t.Setenv("ES_API_KEY", "x")
	path := writeTestConfig(`
listen: ":0"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
acl:
  rules:
    - name: r1
      groups: [team-a]
      indices: ["logs-a"]
      actions: [read]
`)
	store := newPolicyStore()
	var stderr bytes.Buffer
	if err := store.Reload(path, &stderr); err != nil {
		t.Fatal(err)
	}
	id := auth.Identity{Subject: "bob", Groups: []string{"team-a"}}
	if err := store.Current().Decide(id, acl.DecideContext{}, []string{"logs-b"}, acl.ActionRead); err == nil {
		t.Fatal("logs-b should not be covered yet")
	}

	if err := os.WriteFile(path, []byte(`
listen: ":0"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
acl:
  rules:
    - name: r1
      groups: [team-a]
      indices: ["logs-a", "logs-b"]
      actions: [read]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Reload(path, &stderr); err != nil {
		t.Fatal(err)
	}
	if err := store.Current().Decide(id, acl.DecideContext{}, []string{"logs-b"}, acl.ActionRead); err != nil {
		t.Fatalf("logs-b should be covered after reload: %v", err)
	}
}
