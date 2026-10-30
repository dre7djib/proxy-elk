package acl

import (
	"fmt"

	"proxy/internal/auth"
)

// Decide checks whether id may perform action on every one of indices
// (already resolved to concrete index names — see IndexResolver), under
// ctx (F21 conditions). It is fail-closed: any index not covered by a
// matching allow rule denies the whole request, and the error names the
// first index that was refused (F16).
func (p *Policy) Decide(id auth.Identity, ctx DecideContext, indices []string, action Action) error {
	_, err := p.decide(id, ctx, indices, action)
	return err
}

// DecideRule is Decide, but also returns the name of the rule that
// granted the request — empty on deny. Used by the -simulate CLI (F22),
// which reports which rule matched.
func (p *Policy) DecideRule(id auth.Identity, ctx DecideContext, indices []string, action Action) (string, error) {
	return p.decide(id, ctx, indices, action)
}

func (p *Policy) decide(id auth.Identity, ctx DecideContext, indices []string, action Action) (string, error) {
	if p == nil || len(indices) == 0 {
		return "", fmt.Errorf("access denied")
	}
	var rule string
	for _, index := range indices {
		name, ok := p.allows(id, ctx, index, action)
		if !ok {
			return "", fmt.Errorf("access denied to index %s", index)
		}
		rule = name
	}
	return rule, nil
}

func (p *Policy) allows(id auth.Identity, ctx DecideContext, index string, action Action) (string, bool) {
	for _, r := range p.rules {
		if _, ok := r.actions[action]; !ok {
			continue
		}
		if !r.matchesIdentity(id) {
			continue
		}
		if !r.matchesConditions(ctx) {
			continue
		}
		for _, pattern := range r.indices {
			if indexMatches(pattern, index, p.systemIndices) {
				return r.name, true
			}
		}
	}
	return "", false
}

func (r compiledRule) matchesIdentity(id auth.Identity) bool {
	if _, ok := r.users[id.Subject]; ok {
		return true
	}
	for _, g := range id.Groups {
		if _, ok := r.groups[g]; ok {
			return true
		}
	}
	return false
}
