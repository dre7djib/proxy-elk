package main

import (
	"bytes"
	"strings"
	"testing"
)

func simulateConfig(t *testing.T) string {
	t.Helper()
	t.Setenv("ES_API_KEY", "x")
	return writeTestConfig(`
listen: ":0"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY}"
acl:
  rules:
    - name: equipe-a-read
      groups: [equipe-a-viewer]
      indices: [equipe-a-*]
      actions: [read]
`)
}

func TestRunSimulateAllow(t *testing.T) {
	path := simulateConfig(t)
	var stdout, stderr bytes.Buffer
	f := cliFlags{configPath: path, subject: "alice", groups: "equipe-a-viewer", index: "equipe-a-logs", action: "read"}
	if err := runSimulate(f, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(stdout.String()); got != "allow equipe-a-read" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestRunSimulateDenyWrongGroup(t *testing.T) {
	path := simulateConfig(t)
	var stdout, stderr bytes.Buffer
	f := cliFlags{configPath: path, subject: "mallory", groups: "equipe-b-viewer", index: "equipe-a-logs", action: "read"}
	if err := runSimulate(f, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(stdout.String()); got != "access denied to index equipe-a-logs" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestRunSimulateDeniesWriteEvenIfIndexCovered(t *testing.T) {
	path := simulateConfig(t)
	var stdout, stderr bytes.Buffer
	f := cliFlags{configPath: path, subject: "alice", groups: "equipe-a-viewer", index: "equipe-a-logs", action: "write"}
	if err := runSimulate(f, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(stdout.String()); got != "access denied to index equipe-a-logs" {
		t.Fatalf("stdout = %q, a rule granting read must not grant write", got)
	}
}

func TestRunSimulateInvalidConfigIsAnError(t *testing.T) {
	path := writeTestConfig(`
listen: ":0"
elasticsearch:
  url: https://elasticsearch:9200
  api_key: "${env:ES_API_KEY_ABSENT}"
`)
	var stdout, stderr bytes.Buffer
	f := cliFlags{configPath: path, subject: "alice", index: "x", action: "read"}
	if err := runSimulate(f, &stdout, &stderr); err == nil {
		t.Fatal("expected an error for a config missing its secret")
	}
}

func TestRunSimulateInvalidTimeIsAnError(t *testing.T) {
	path := simulateConfig(t)
	var stdout, stderr bytes.Buffer
	f := cliFlags{configPath: path, subject: "alice", groups: "equipe-a-viewer", index: "equipe-a-logs", action: "read", time: "not-rfc3339"}
	if err := runSimulate(f, &stdout, &stderr); err == nil {
		t.Fatal("expected an error for an invalid -time value")
	}
}

func TestRunSimulateDoesNotListen(t *testing.T) {
	path := simulateConfig(t)
	var stdout, stderr bytes.Buffer
	f := cliFlags{configPath: path, subject: "alice", groups: "equipe-a-viewer", index: "equipe-a-logs", action: "read"}
	if err := runSimulate(f, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() == 0 {
		t.Fatal("expected a decision line on stdout")
	}
}
