// Package limits resolves and enforces per-role request quotas (F25): max
// duration, max response size, requests per minute.
package limits

import (
	"fmt"
	"time"

	"proxy/internal/auth"
)

// Role is one YAML-configured quota entry. Groups is empty for the
// default entry (it matches every identity); Parse requires it to be
// non-empty for every entry in Roles.
type Role struct {
	Groups            []string `yaml:"groups" json:"groups"`
	MaxDuration       string   `yaml:"max_duration" json:"max_duration"`
	MaxResultBytes    int64    `yaml:"max_result_bytes" json:"max_result_bytes"`
	RequestsPerMinute int      `yaml:"requests_per_minute" json:"requests_per_minute"`
}

// Quota is a compiled, resolved set of limits for one caller.
type Quota struct {
	MaxDuration       time.Duration
	MaxResultBytes    int64
	RequestsPerMinute int
}

type compiledRole struct {
	groups map[string]struct{}
	quota  Quota
}

// Limits is a validated, ready-to-evaluate set of role quotas plus an
// optional default. A nil *Limits always resolves to no limit.
type Limits struct {
	def   *Quota
	roles []compiledRole
}

// Parse validates def and roles and compiles them into Limits. A group
// used in more than one entry of roles is rejected. knownGroups, when
// non-empty, restricts which groups a role may reference — same rule as
// acl.Parse.
func Parse(def *Role, roles []Role, knownGroups []string) (*Limits, error) {
	var knownSet map[string]struct{}
	if len(knownGroups) > 0 {
		knownSet = make(map[string]struct{}, len(knownGroups))
		for _, g := range knownGroups {
			knownSet[g] = struct{}{}
		}
	}

	l := &Limits{}
	if def != nil {
		q, err := compileQuota(*def)
		if err != nil {
			return nil, fmt.Errorf("limits.default: %w", err)
		}
		l.def = &q
	}

	seen := make(map[string]struct{})
	for i, r := range roles {
		if len(r.Groups) == 0 {
			return nil, fmt.Errorf("limits.roles[%d]: groups must not be empty", i)
		}
		for _, g := range r.Groups {
			if _, dup := seen[g]; dup {
				return nil, fmt.Errorf("limits.roles[%d]: group %q used in more than one entry", i, g)
			}
			seen[g] = struct{}{}
			if knownSet != nil {
				if _, ok := knownSet[g]; !ok {
					return nil, fmt.Errorf("limits.roles[%d]: unknown group %q", i, g)
				}
			}
		}
		q, err := compileQuota(r)
		if err != nil {
			return nil, fmt.Errorf("limits.roles[%d]: %w", i, err)
		}
		groups := make(map[string]struct{}, len(r.Groups))
		for _, g := range r.Groups {
			groups[g] = struct{}{}
		}
		l.roles = append(l.roles, compiledRole{groups: groups, quota: q})
	}
	return l, nil
}

func compileQuota(r Role) (Quota, error) {
	d, err := time.ParseDuration(r.MaxDuration)
	if err != nil || d <= 0 {
		return Quota{}, fmt.Errorf(`max_duration must be a positive Go duration (e.g. "30s")`)
	}
	if r.MaxResultBytes < 1 {
		return Quota{}, fmt.Errorf("max_result_bytes must be at least 1")
	}
	if r.RequestsPerMinute < 1 {
		return Quota{}, fmt.Errorf("requests_per_minute must be at least 1")
	}
	return Quota{MaxDuration: d, MaxResultBytes: r.MaxResultBytes, RequestsPerMinute: r.RequestsPerMinute}, nil
}

// Resolve returns the quota applying to id: the minimum of each role
// whose groups intersect id.Groups, or the default when none match, or
// nil (no limit) when neither applies. A nil *Limits is always no limit.
func (l *Limits) Resolve(id auth.Identity) *Quota {
	if l == nil {
		return nil
	}
	var q *Quota
	for _, r := range l.roles {
		if !matches(r.groups, id.Groups) {
			continue
		}
		if q == nil {
			cp := r.quota
			q = &cp
			continue
		}
		if r.quota.MaxDuration < q.MaxDuration {
			q.MaxDuration = r.quota.MaxDuration
		}
		if r.quota.MaxResultBytes < q.MaxResultBytes {
			q.MaxResultBytes = r.quota.MaxResultBytes
		}
		if r.quota.RequestsPerMinute < q.RequestsPerMinute {
			q.RequestsPerMinute = r.quota.RequestsPerMinute
		}
	}
	if q != nil {
		return q
	}
	if l.def != nil {
		cp := *l.def
		return &cp
	}
	return nil
}

func matches(groups map[string]struct{}, callerGroups []string) bool {
	for _, g := range callerGroups {
		if _, ok := groups[g]; ok {
			return true
		}
	}
	return false
}
