package config

import (
	"os"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"proxy/internal/acl"
	"proxy/internal/auth"
)

// aclCase is one row of configs/acl_cases.yaml (F24): a Decide call
// against the rules in configs/proxy.example.yaml, and the expected
// outcome.
type aclCase struct {
	Name    string   `yaml:"name"`
	Subject string   `yaml:"subject"`
	Groups  []string `yaml:"groups"`
	Index   string   `yaml:"index"`
	Action  string   `yaml:"action"`
	Allow   string   `yaml:"allow"` // expected matching rule name; empty means Deny must be true
	Deny    bool     `yaml:"deny"`
}

type aclCasesFile struct {
	Cases []aclCase `yaml:"cases"`
}

// TestACLCases replays every case in configs/acl_cases.yaml against the
// ACL rules actually shipped in configs/proxy.example.yaml (F24): a case
// fails the moment the example config's rules and the recorded cases
// drift apart.
func TestACLCases(t *testing.T) {
	const secret = "acl-cases-secret-value"
	t.Setenv("ES_API_KEY", secret)
	t.Setenv("ES_RUN_AS_PASSWORD", "acl-cases-run-as-secret")
	t.Setenv("ES_SHADOW_PASSWORD", "acl-cases-shadow-secret")
	t.Setenv("OIDC_CLIENT_SECRET", "acl-cases-oidc-secret")
	t.Setenv("LDAP_BIND_PASSWORD", "acl-cases-ldap-secret")
	t.Setenv("SESSION_SECRET", testSessionSecret)

	cfg, _, err := Load("../../configs/proxy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := acl.Parse(cfg.ACL.Rules, cfg.ACL.KnownGroups, cfg.ACL.SystemIndices)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile("../../configs/acl_cases.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var file aclCasesFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("configs/acl_cases.yaml has no cases")
	}

	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			id := auth.Identity{Subject: c.Subject, Groups: c.Groups}
			ctx := acl.DecideContext{Time: time.Now()}
			name, err := policy.DecideRule(id, ctx, []string{c.Index}, acl.Action(c.Action))

			if c.Allow != "" {
				if err != nil {
					t.Fatalf("expected allow by %q, got deny: %v", c.Allow, err)
				}
				if name != c.Allow {
					t.Fatalf("allowed by %q, want %q", name, c.Allow)
				}
				return
			}
			if !c.Deny {
				t.Fatalf("case %q sets neither allow nor deny", c.Name)
			}
			if err == nil {
				t.Fatalf("expected deny, got allow by %q", name)
			}
		})
	}
}
