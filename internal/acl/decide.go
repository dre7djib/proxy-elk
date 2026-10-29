package acl

import (
	"fmt"

	"proxy/internal/auth"
)

// Decide checks whether id may perform action on every one of indices
// (already resolved to concrete index names — see IndexResolver). It is
// fail-closed: any index not covered by a matching allow rule denies the
// whole request.
func (p *Policy) Decide(id auth.Identity, indices []string, action Action) error {
	if p == nil {
		return fmt.Errorf("access denied")
	}
	for _, index := range indices {
		if !p.allows(id, index, action) {
			return fmt.Errorf("access denied")
		}
	}
	return nil
}

func (p *Policy) allows(id auth.Identity, index string, action Action) bool {
	for _, r := range p.rules {
		if _, ok := r.actions[action]; !ok {
			continue
		}
		if !r.matchesIdentity(id) {
			continue
		}
		for _, pattern := range r.indices {
			if indexMatches(pattern, index, p.systemIndices) {
				return true
			}
		}
	}
	return false
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
