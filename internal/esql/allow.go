package esql

import (
	"context"
	"fmt"

	"proxy/internal/acl"
	"proxy/internal/auth"
)

// PolicySources resolves an ENRICH policy name to the concrete source
// index names it reads. Unknown policies must return an error so the
// caller can deny (fail-closed).
type PolicySources interface {
	SourceIndices(ctx context.Context, policy string) ([]string, error)
}

// Allow checks that id may read every index the query touches, including
// ENRICH policy source indices. Uncertain parses and lookup failures deny.
// A certain query that reads no indices (ROW / SHOW) is allowed.
func Allow(ctx context.Context, query string, id auth.Identity, dc acl.DecideContext, policy *acl.Policy, resolver acl.IndexResolver, enrich PolicySources) error {
	p := Parse(query)
	if p.Uncertain {
		return fmt.Errorf("access denied: cannot determine indices read by ES|QL query")
	}
	indices := append([]string(nil), p.Indices...)
	if len(p.Policies) > 0 {
		if enrich == nil {
			return fmt.Errorf("access denied: ENRICH is not configured")
		}
		for _, name := range p.Policies {
			srcs, err := enrich.SourceIndices(ctx, name)
			if err != nil {
				return fmt.Errorf("access denied: enrich policy %q: %w", name, err)
			}
			if len(srcs) == 0 {
				return fmt.Errorf("access denied: enrich policy %q has no source indices", name)
			}
			indices = append(indices, srcs...)
		}
	}
	if len(indices) == 0 {
		return nil
	}
	if resolver == nil {
		return fmt.Errorf("access denied: index resolver not configured")
	}
	resolved, err := resolver.Resolve(ctx, indices)
	if err != nil {
		return fmt.Errorf("access denied: index resolution failed")
	}
	if len(resolved) == 0 {
		// Wildcard that matched nothing: deny rather than skip Decide.
		return fmt.Errorf("access denied")
	}
	return policy.Decide(id, dc, resolved, acl.ActionRead)
}
