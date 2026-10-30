package acl

import (
	"context"
	"testing"

	"proxy/internal/auth"
)

// fakeResolver is a test IndexResolver: it maps names to a fixed set of
// concrete indices, the same shape a real ES _resolve/index client returns.
type fakeResolver map[string][]string

func (f fakeResolver) Resolve(_ context.Context, names []string) ([]string, error) {
	var out []string
	for _, n := range names {
		if concrete, ok := f[n]; ok {
			out = append(out, concrete...)
			continue
		}
		out = append(out, n)
	}
	return out, nil
}

// TestAliasDoesNotBypassACL: a rule granting "public" must not let a caller
// reach the "secret" index an alias with that name actually points to
// (F15). The caller always gets decided against resolved, concrete names.
func TestAliasDoesNotBypassACL(t *testing.T) {
	resolver := fakeResolver{"public": {"secret"}}
	p, err := Parse([]Rule{{
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
	if err := p.Decide(id, DecideContext{}, resolved, ActionRead); err == nil {
		t.Fatal("alias resolving to an ungranted index must be denied")
	}
}

func TestAliasResolvingToGrantedIndexIsAllowed(t *testing.T) {
	resolver := fakeResolver{"public": {"shared-ref"}}
	p, err := Parse([]Rule{{
		Name: "r1", Groups: []string{"team-a"}, Indices: []string{"shared-ref"}, Actions: []string{"read"},
	}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := auth.Identity{Subject: "bob", Groups: []string{"team-a"}}

	resolved, err := resolver.Resolve(context.Background(), []string{"public"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Decide(id, DecideContext{}, resolved, ActionRead); err != nil {
		t.Fatalf("resolved index granted directly should be allowed: %v", err)
	}
}
