package main

import (
	"os"
	"strings"
	"testing"
)

func TestSystemdUnit(t *testing.T) {
	b, err := os.ReadFile("../../deploy/systemd/proxy-elk.service")
	if err != nil {
		t.Fatal(err)
	}
	unit := string(b)
	for _, want := range []string{
		"User=proxy", "Group=proxy",
		"ExecStart=/usr/local/bin/proxy -config /etc/proxy/proxy.yaml",
		"Restart=on-failure", "WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit missing %q", want)
		}
	}
	if strings.Contains(unit, "EnvironmentFile") || strings.Contains(unit, "Environment=") {
		t.Error("unit must not carry secrets through the environment")
	}
}

func TestSystemdYAMLSecretsAreFiles(t *testing.T) {
	b, err := os.ReadFile("../../deploy/systemd/proxy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "${env:") {
		t.Error("systemd YAML must reference secrets with ${file:} only")
	}
}
