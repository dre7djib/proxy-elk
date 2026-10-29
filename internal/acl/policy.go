// Package acl decides which indices and actions a caller may use.
//
// Rules are allow-only; anything not explicitly allowed is denied
// (fail-closed, F14/F19). The MVP only ever grants the "read" action.
package acl

import (
	"fmt"
	"path"
)

// Action is a permission a rule can grant. The only value accepted by
// Parse in this MVP is ActionRead; write support is J1-08.
type Action string

// ActionRead is the only action a rule may grant in this MVP.
const ActionRead Action = "read"

// defaultSystemIndices is used when a Policy's system index list isn't
// configured. F17: a wildcard rule pattern never covers these.
var defaultSystemIndices = []string{".kibana*", ".security*", ".tasks*", ".enrich-*"}

// Rule is one YAML-configured ACL rule. Exactly one of Users/Groups must be
// non-empty for the rule to ever match (enforced by Parse).
type Rule struct {
	Name    string   `yaml:"name" json:"name"`
	Users   []string `yaml:"users" json:"users"`
	Groups  []string `yaml:"groups" json:"groups"`
	Indices []string `yaml:"indices" json:"indices"`
	Actions []string `yaml:"actions" json:"actions"`
}

type compiledRule struct {
	name    string
	users   map[string]struct{}
	groups  map[string]struct{}
	indices []string
	actions map[Action]struct{}
}

// Policy is a validated, ready-to-evaluate set of ACL rules.
type Policy struct {
	rules         []compiledRule
	systemIndices []string
}

// Parse validates rules (F19) and compiles them into a Policy. knownGroups,
// when non-empty, restricts which groups a rule may reference; an unknown
// group fails validation. systemIndices overrides the default F17 system
// index patterns; empty uses the default.
func Parse(rules []Rule, knownGroups []string, systemIndices []string) (*Policy, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("acl: at least one rule is required")
	}
	if len(systemIndices) == 0 {
		systemIndices = defaultSystemIndices
	}
	var knownGroupSet map[string]struct{}
	if len(knownGroups) > 0 {
		knownGroupSet = make(map[string]struct{}, len(knownGroups))
		for _, g := range knownGroups {
			knownGroupSet[g] = struct{}{}
		}
	}

	names := make(map[string]struct{}, len(rules))
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		if r.Name == "" {
			return nil, fmt.Errorf("acl: rule has no name")
		}
		if _, dup := names[r.Name]; dup {
			return nil, fmt.Errorf("acl: duplicate rule name %q", r.Name)
		}
		names[r.Name] = struct{}{}

		if len(r.Users) == 0 && len(r.Groups) == 0 {
			return nil, fmt.Errorf("acl: rule %q must set users or groups", r.Name)
		}
		if len(r.Indices) == 0 {
			return nil, fmt.Errorf("acl: rule %q has no indices", r.Name)
		}
		if len(r.Actions) == 0 {
			return nil, fmt.Errorf("acl: rule %q has no actions", r.Name)
		}

		if knownGroupSet != nil {
			for _, g := range r.Groups {
				if _, ok := knownGroupSet[g]; !ok {
					return nil, fmt.Errorf("acl: rule %q references unknown group %q", r.Name, g)
				}
			}
		}

		actions := make(map[Action]struct{}, len(r.Actions))
		for _, a := range r.Actions {
			if Action(a) != ActionRead {
				return nil, fmt.Errorf("acl: rule %q has unsupported action %q (only %q is allowed)", r.Name, a, ActionRead)
			}
			actions[Action(a)] = struct{}{}
		}

		for _, pattern := range r.Indices {
			if _, err := path.Match(pattern, "probe"); err != nil {
				return nil, fmt.Errorf("acl: rule %q has invalid index pattern %q: %w", r.Name, pattern, err)
			}
		}

		cr := compiledRule{
			name:    r.Name,
			indices: append([]string(nil), r.Indices...),
			actions: actions,
		}
		if len(r.Users) > 0 {
			cr.users = make(map[string]struct{}, len(r.Users))
			for _, u := range r.Users {
				cr.users[u] = struct{}{}
			}
		}
		if len(r.Groups) > 0 {
			cr.groups = make(map[string]struct{}, len(r.Groups))
			for _, g := range r.Groups {
				cr.groups[g] = struct{}{}
			}
		}
		compiled = append(compiled, cr)
	}

	return &Policy{rules: compiled, systemIndices: systemIndices}, nil
}
