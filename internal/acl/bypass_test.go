package acl

import (
	"context"
	"testing"

	"proxy/internal/auth"
)

// TestBypassBattery is the J1-14 battery: every case here must be refused.
// Rule in force: group "team-a", indices "logs-*" or "public", action
// "read". The resolver is the fakeResolver from resolve_test.go.
func TestBypassBattery(t *testing.T) {
	policy, err := Parse([]Rule{{
		Name: "r1", Groups: []string{"team-a"}, Indices: []string{"logs-*", "public"}, Actions: []string{"read"},
	}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := auth.Identity{Subject: "bob", Groups: []string{"team-a"}}

	cases := []struct {
		name     string
		resolved []string
	}{
		{"alias public to system index", []string{".security-7"}},
		{"wildcard resolved with support index", []string{"logs-1", ".ds-logs-0001"}},
		{"wildcard star does not cover secret", []string{"logs-1", "secret"}},
		{"pattern does not cover logsecret", []string{"logsecret"}},
		{"pattern does not cover other-logs-1", []string{"other-logs-1"}},
		{"empty index list", []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := policy.Decide(id, DecideContext{}, c.resolved, ActionRead); err == nil {
				t.Fatalf("%s: expected deny", c.name)
			}
		})
	}
}

// TestBypassBatteryStarWildcardDoesNotCoverOthers mirrors the "*" case from
// the plan with its own resolver, since "*" isn't in the shared rule above.
func TestBypassBatteryStarWildcardDoesNotCoverOthers(t *testing.T) {
	policy, err := Parse([]Rule{{
		Name: "r1", Groups: []string{"team-a"}, Indices: []string{"*"}, Actions: []string{"read"},
	}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := auth.Identity{Subject: "bob", Groups: []string{"team-a"}}

	if err := policy.Decide(id, DecideContext{}, []string{"logs-1", "secret"}, ActionRead); err != nil {
		t.Fatalf("logs-1 and secret are both non-system and matched by *: expected allow, got %v", err)
	}
	if err := policy.Decide(id, DecideContext{}, []string{".security-7"}, ActionRead); err == nil {
		t.Fatal("* must not cover a system index")
	}
}

// TestBypassBatteryClassifyThenDecide: a resolved index covered by the
// rule ("logs-1") must still be refused when the path resolves, after
// normalization, to an admin category. The refusal comes from the
// category, not from the index name.
func TestBypassBatteryClassifyThenDecide(t *testing.T) {
	policy, err := Parse([]Rule{{
		Name: "r1", Groups: []string{"team-a"}, Indices: []string{"logs-*"}, Actions: []string{"read"},
	}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := auth.Identity{Subject: "bob", Groups: []string{"team-a"}}

	cases := []struct {
		name, method, path string
	}{
		{"double slash cluster health", "GET", "//_cluster/health"},
		{"dotdot into bulk", "POST", "/logs-a/../_bulk"},
		{"dotdot into security user", "GET", "/logs-a/_search/../../_security/user"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			action := Classify(c.method, c.path)
			if err := policy.Decide(id, DecideContext{}, []string{"logs-1"}, action); err == nil {
				t.Fatalf("%s: expected deny for category %q", c.name, action)
			}
		})
	}
}

// TestBypassBatteryAliasToSystemIndex exercises the alias case end to end
// through the fakeResolver, as the plan describes it.
func TestBypassBatteryAliasToSystemIndex(t *testing.T) {
	resolver := fakeResolver{"public": {".security-7"}}
	policy, err := Parse([]Rule{{
		Name: "r1", Groups: []string{"team-a"}, Indices: []string{"public"}, Actions: []string{"read"},
	}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := auth.Identity{Subject: "bob", Groups: []string{"team-a"}}

	resolved, err := resolver.Resolve(context.Background(), []string{"public"})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Decide(id, DecideContext{}, resolved, ActionRead); err == nil {
		t.Fatal("alias resolving to a system index must be denied even though the rule names public")
	}
}

// TestBypassBatteryWildcardSupportIndex exercises the logs-* case end to
// end through the fakeResolver: the support index .ds-logs-0001 is not
// covered by logs-* once it is recognized as a system (dot-prefixed) index.
func TestBypassBatteryWildcardSupportIndex(t *testing.T) {
	resolver := fakeResolver{"logs-*": {"logs-1", ".ds-logs-0001"}}
	policy, err := Parse([]Rule{{
		Name: "r1", Groups: []string{"team-a"}, Indices: []string{"logs-*"}, Actions: []string{"read"},
	}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := auth.Identity{Subject: "bob", Groups: []string{"team-a"}}

	resolved, err := resolver.Resolve(context.Background(), []string{"logs-*"})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Decide(id, DecideContext{}, resolved, ActionRead); err == nil {
		t.Fatal("support index .ds-logs-0001 must not be swept in by logs-*")
	}
}
