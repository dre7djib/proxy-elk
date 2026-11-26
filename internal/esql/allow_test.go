package esql

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"proxy/internal/acl"
	"proxy/internal/auth"
)

type echoResolver struct{}

func (echoResolver) Resolve(_ context.Context, names []string) ([]string, error) {
	return names, nil
}

type mapEnrich map[string][]string

func (m mapEnrich) SourceIndices(_ context.Context, policy string) ([]string, error) {
	idxs, ok := m[policy]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return idxs, nil
}

func testPolicy(t *testing.T) *acl.Policy {
	t.Helper()
	p, err := acl.Parse([]acl.Rule{{
		Name: "a", Groups: []string{"equipe-a-viewer"}, Indices: []string{"equipe-a-*"}, Actions: []string{"read"},
	}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAllowSameTeamENRICH(t *testing.T) {
	id := auth.Identity{Subject: "alice", Groups: []string{"equipe-a-viewer"}}
	q := `FROM equipe-a-sp05-logs | ENRICH sp05-owners-a-policy ON host`
	enrich := mapEnrich{"sp05-owners-a-policy": {"equipe-a-sp05-owners"}}
	if err := Allow(context.Background(), q, id, acl.DecideContext{}, testPolicy(t), echoResolver{}, enrich); err != nil {
		t.Fatal(err)
	}
}

func TestAllowCrossTeamENRICHDenied(t *testing.T) {
	id := auth.Identity{Subject: "alice", Groups: []string{"equipe-a-viewer"}}
	q := `FROM equipe-a-sp05-logs | ENRICH sp05-owners-b-policy ON host`
	enrich := mapEnrich{"sp05-owners-b-policy": {"equipe-b-sp05-owners"}}
	err := Allow(context.Background(), q, id, acl.DecideContext{}, testPolicy(t), echoResolver{}, enrich)
	if err == nil || !strings.Contains(err.Error(), "equipe-b-sp05-owners") {
		t.Fatalf("want deny naming equipe-b source, got %v", err)
	}
}

func TestAllowUnknownPolicyDenied(t *testing.T) {
	id := auth.Identity{Subject: "alice", Groups: []string{"equipe-a-viewer"}}
	q := `FROM equipe-a-logs | ENRICH missing-policy ON host`
	err := Allow(context.Background(), q, id, acl.DecideContext{}, testPolicy(t), echoResolver{}, mapEnrich{})
	if err == nil {
		t.Fatal("expected deny")
	}
}

func TestAllowUncertainDenied(t *testing.T) {
	id := auth.Identity{Subject: "alice", Groups: []string{"equipe-a-viewer"}}
	err := Allow(context.Background(), "bad", id, acl.DecideContext{}, testPolicy(t), echoResolver{}, nil)
	if err == nil {
		t.Fatal("expected deny")
	}
}

func TestAllowLOOKUPJOINOtherTeamDenied(t *testing.T) {
	id := auth.Identity{Subject: "alice", Groups: []string{"equipe-a-viewer"}}
	q := `FROM equipe-a-logs | LOOKUP JOIN equipe-b-hosts ON host`
	err := Allow(context.Background(), q, id, acl.DecideContext{}, testPolicy(t), echoResolver{}, nil)
	if err == nil {
		t.Fatal("expected deny")
	}
}

func TestAllowROWWithoutIndices(t *testing.T) {
	id := auth.Identity{Subject: "alice", Groups: []string{"equipe-a-viewer"}}
	if err := Allow(context.Background(), `ROW a = 1`, id, acl.DecideContext{}, testPolicy(t), echoResolver{}, nil); err != nil {
		t.Fatal(err)
	}
}
