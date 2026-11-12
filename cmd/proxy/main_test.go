package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRefusesMissingSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.yaml")
	body := []byte(`
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY_ABSENT}"
  run_as_user: proxy_service
  run_as_password: "${env:ES_RUN_AS_PASSWORD}"
  shadow_password: "${env:ES_SHADOW_PASSWORD}"
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"-config", path}, ioDiscard(t), ioDiscard(t))
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunPrintsRedactedConfig(t *testing.T) {
	const secret = "startup-secret-value"
	t.Setenv("ES_API_KEY", secret)
	t.Setenv("ES_RUN_AS_PASSWORD", "x")
	t.Setenv("ES_SHADOW_PASSWORD", "x")
	path := filepath.Join(t.TempDir(), "proxy.yaml")
	body := []byte(`
listen: ":8080"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
  run_as_user: proxy_service
  run_as_password: "${env:ES_RUN_AS_PASSWORD}"
  shadow_password: "${env:ES_SHADOW_PASSWORD}"
acl:
  rules:
    - name: default
      groups: [testers]
      indices: ["*"]
      actions: [read]
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-config", path}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
		t.Fatalf("startup output leaked secret\nstdout=%s\nstderr=%s", stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"api_key":"***"`) {
		t.Fatalf("stdout = %s", stdout.String())
	}
}

func ioDiscard(t *testing.T) *bytes.Buffer {
	t.Helper()
	return &bytes.Buffer{}
}
