package acl

import (
	"testing"

	"proxy/internal/auth"
)

func TestDecideWildcardMatchesPrefix(t *testing.T) {
	p, err := Parse([]Rule{{
		Name: "r1", Groups: []string{"team-a"}, Indices: []string{"logs-*"}, Actions: []string{"read"},
	}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := auth.Identity{Subject: "bob", Groups: []string{"team-a"}}

	if err := p.Decide(id, DecideContext{}, []string{"logs-1"}, ActionRead); err != nil {
		t.Fatalf("logs-1 should be allowed: %v", err)
	}
	if err := p.Decide(id, DecideContext{}, []string{"other"}, ActionRead); err == nil {
		t.Fatal("other should be denied")
	}
}

func TestDecideDeniesWithoutMatchingIdentity(t *testing.T) {
	p, err := Parse([]Rule{{
		Name: "r1", Groups: []string{"team-a"}, Indices: []string{"logs-*"}, Actions: []string{"read"},
	}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := auth.Identity{Subject: "bob", Groups: []string{"team-b"}}
	if err := p.Decide(id, DecideContext{}, []string{"logs-1"}, ActionRead); err == nil {
		t.Fatal("expected deny for non-matching identity")
	}
}

func TestDecideMatchesByUser(t *testing.T) {
	p, err := Parse([]Rule{{
		Name: "r1", Users: []string{"alice"}, Indices: []string{"alice-scratch"}, Actions: []string{"read"},
	}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Decide(auth.Identity{Subject: "alice"}, DecideContext{}, []string{"alice-scratch"}, ActionRead); err != nil {
		t.Fatalf("alice should be allowed: %v", err)
	}
	if err := p.Decide(auth.Identity{Subject: "bob"}, DecideContext{}, []string{"alice-scratch"}, ActionRead); err == nil {
		t.Fatal("bob should be denied")
	}
}

func TestDecideSystemIndexNotCoveredByWildcard(t *testing.T) {
	p, err := Parse([]Rule{{
		Name: "r1", Groups: []string{"team-a"}, Indices: []string{"*"}, Actions: []string{"read"},
	}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := auth.Identity{Subject: "bob", Groups: []string{"team-a"}}
	if err := p.Decide(id, DecideContext{}, []string{".security-7"}, ActionRead); err == nil {
		t.Fatal("wildcard rule must not cover a system index")
	}
}

func TestDecideSystemIndexAllowedByExplicitRule(t *testing.T) {
	p, err := Parse([]Rule{{
		Name: "r1", Groups: []string{"team-a"}, Indices: []string{".kibana*"}, Actions: []string{"read"},
	}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := auth.Identity{Subject: "bob", Groups: []string{"team-a"}}
	if err := p.Decide(id, DecideContext{}, []string{".kibana_1"}, ActionRead); err != nil {
		t.Fatalf(".kibana_1 should be allowed: %v", err)
	}
}

func TestDecideConfiguredSystemPatternGatesLikeDotPrefix(t *testing.T) {
	p, err := Parse([]Rule{{
		Name: "wide", Groups: []string{"team-a"}, Indices: []string{"*"}, Actions: []string{"read"},
	}, {
		Name: "audit", Groups: []string{"team-a"}, Indices: []string{"audit-*"}, Actions: []string{"read"},
	}}, nil, []string{"audit-*"})
	if err != nil {
		t.Fatal(err)
	}
	id := auth.Identity{Subject: "bob", Groups: []string{"team-a"}}
	if err := p.Decide(id, DecideContext{}, []string{"audit-2024"}, ActionRead); err != nil {
		t.Fatalf("explicit audit-* rule should allow: %v", err)
	}
}

func TestDecideNilPolicyDeniesEverything(t *testing.T) {
	var p *Policy
	if err := p.Decide(auth.Identity{Subject: "bob"}, DecideContext{}, []string{"anything"}, ActionRead); err == nil {
		t.Fatal("nil policy must deny")
	}
}

func TestDecideDenyMessageNamesFirstRefusedIndex(t *testing.T) {
	p, err := Parse([]Rule{{
		Name: "r1", Groups: []string{"team-a"}, Indices: []string{"logs-a"}, Actions: []string{"read"},
	}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := auth.Identity{Subject: "bob", Groups: []string{"team-a"}}
	err = p.Decide(id, DecideContext{}, []string{"logs-a", "logs-b"}, ActionRead)
	if err == nil || err.Error() != "access denied to index logs-b" {
		t.Fatalf("err = %v, want access denied to index logs-b", err)
	}
}

func TestDecideRuleReturnsMatchingRuleName(t *testing.T) {
	p, err := Parse([]Rule{{
		Name: "equipe-a-read", Groups: []string{"team-a"}, Indices: []string{"logs-*"}, Actions: []string{"read"},
	}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := auth.Identity{Subject: "bob", Groups: []string{"team-a"}}
	name, err := p.DecideRule(id, DecideContext{}, []string{"logs-1"}, ActionRead)
	if err != nil {
		t.Fatal(err)
	}
	if name != "equipe-a-read" {
		t.Fatalf("rule name = %q", name)
	}
}

func TestDecideOnlyReadActionCanBeGranted(t *testing.T) {
	p, err := Parse([]Rule{{
		Name: "r1", Groups: []string{"team-a"}, Indices: []string{"logs-*"}, Actions: []string{"read"},
	}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := auth.Identity{Subject: "bob", Groups: []string{"team-a"}}
	for _, action := range []Action{ActionWrite, ActionClusterAdmin} {
		if err := p.Decide(id, DecideContext{}, []string{"logs-1"}, action); err == nil {
			t.Fatalf("%s should be denied even though the index is covered for read", action)
		}
	}
}
