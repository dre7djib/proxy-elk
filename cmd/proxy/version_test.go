package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The printed version must be the one injected by -ldflags.
func TestVersionFlagPrintsInjectedVersion(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "proxy")
	build := exec.Command("go", "build", "-ldflags", "-X main.version=9.9.9-test", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	out, err := exec.Command(bin, "-version").Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != "9.9.9-test" {
		t.Fatalf("version = %q, want 9.9.9-test", got)
	}
}
