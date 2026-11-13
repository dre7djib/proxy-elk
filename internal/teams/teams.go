// Package teams parses the YAML `teams` section: team, viewer/editor/admin
// levels, and the external (LDAP/OIDC) groups mapped to each level. It
// only derives ACL read rules and (team, level) pairs; creating the
// Elasticsearch roles and Kibana spaces is a separate sync step.
package teams

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"proxy/internal/acl"
)

// Level is a team access level.
type Level string

const (
	Viewer Level = "viewer"
	Editor Level = "editor"
	Admin  Level = "admin"
)

// levelOrder is the fixed iteration order, so output is deterministic.
var levelOrder = []Level{Viewer, Editor, Admin}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// Team is one YAML entry. Levels maps a level name to the external groups
// that hold it.
type Team struct {
	Name    string              `yaml:"name" json:"name"`
	Indices []string            `yaml:"indices" json:"indices"`
	Space   string              `yaml:"space" json:"space"`
	Levels  map[string][]string `yaml:"levels" json:"levels"`
}

// Membership is one (team, level) pair a caller holds.
type Membership struct {
	Team  string
	Level Level
	Space string
}

// Config is a validated set of teams.
type Config struct {
	teams   []Team
	byGroup map[string]Membership // enforces one pair per group
}

// RoleName is the Elasticsearch role name reserved for a team level.
func RoleName(team string, l Level) string { return team + "_" + string(l) }

// KibanaBase is the Kibana base privilege for a level: read for viewer,
// all for editor and admin.
func KibanaBase(l Level) string {
	if l == Viewer {
		return "read"
	}
	return "all"
}

// Parse validates teams. Empty input yields an empty, valid Config.
func Parse(teams []Team) (*Config, error) {
	c := &Config{byGroup: map[string]Membership{}}
	names := map[string]struct{}{}
	spaces := map[string]struct{}{}
	for i, t := range teams {
		if t.Name == "" {
			return nil, fmt.Errorf("teams: team #%d has no name", i+1)
		}
		if !idPattern.MatchString(t.Name) {
			return nil, fmt.Errorf("teams: team name %q must match %s", t.Name, idPattern)
		}
		if _, dup := names[t.Name]; dup {
			return nil, fmt.Errorf("teams: duplicate team %q", t.Name)
		}
		names[t.Name] = struct{}{}

		if t.Space == "" {
			return nil, fmt.Errorf("teams: team %q has no space", t.Name)
		}
		if !idPattern.MatchString(t.Space) {
			return nil, fmt.Errorf("teams: team %q space %q must match %s", t.Name, t.Space, idPattern)
		}
		if _, dup := spaces[t.Space]; dup {
			return nil, fmt.Errorf("teams: duplicate space %q", t.Space)
		}
		spaces[t.Space] = struct{}{}

		if len(t.Indices) == 0 {
			return nil, fmt.Errorf("teams: team %q has no indices", t.Name)
		}
		for _, p := range t.Indices {
			if strings.HasPrefix(p, ".") {
				return nil, fmt.Errorf("teams: team %q index pattern %q must not start with '.'", t.Name, p)
			}
			if _, err := path.Match(p, "probe"); err != nil {
				return nil, fmt.Errorf("teams: team %q has invalid index pattern %q: %w", t.Name, p, err)
			}
		}

		if len(t.Levels) == 0 {
			return nil, fmt.Errorf("teams: team %q has no levels", t.Name)
		}
		for name, groups := range t.Levels {
			l := Level(name)
			if l != Viewer && l != Editor && l != Admin {
				return nil, fmt.Errorf("teams: team %q has unknown level %q (viewer, editor or admin)", t.Name, name)
			}
			if len(groups) == 0 {
				return nil, fmt.Errorf("teams: team %q level %q has no group", t.Name, name)
			}
			for _, g := range groups {
				if g == "" {
					return nil, fmt.Errorf("teams: team %q level %q has an empty group", t.Name, name)
				}
				if prev, dup := c.byGroup[g]; dup {
					return nil, fmt.Errorf("teams: group %q is already mapped to %s/%s", g, prev.Team, prev.Level)
				}
				c.byGroup[g] = Membership{Team: t.Name, Level: l, Space: t.Space}
			}
		}
		c.teams = append(c.teams, t)
	}
	return c, nil
}

// Rules returns one read rule per team, named team:<name>, for the union
// of its level groups.
func (c *Config) Rules() []acl.Rule {
	rules := make([]acl.Rule, 0, len(c.teams))
	for _, t := range c.teams {
		var groups []string
		for _, l := range levelOrder {
			groups = append(groups, t.Levels[string(l)]...)
		}
		rules = append(rules, acl.Rule{
			Name:    "team:" + t.Name,
			Groups:  groups,
			Indices: append([]string(nil), t.Indices...),
			Actions: []string{string(acl.ActionRead)},
		})
	}
	return rules
}

// Groups returns every group referenced by any team.
func (c *Config) Groups() []string {
	var out []string
	for _, t := range c.teams {
		for _, l := range levelOrder {
			out = append(out, t.Levels[string(l)]...)
		}
	}
	return out
}

// Memberships returns every (team, level) pair the groups match, in YAML
// order (team, then viewer/editor/admin).
func (c *Config) Memberships(groups []string) []Membership {
	var out []Membership
	for _, t := range c.teams {
		for _, l := range levelOrder {
			for _, g := range t.Levels[string(l)] {
				if contains(groups, g) {
					out = append(out, Membership{Team: t.Name, Level: l, Space: t.Space})
				}
			}
		}
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// IndexPrivilege is one Elasticsearch index grant of a Kibana role body.
type IndexPrivilege struct {
	Names      []string `json:"names"`
	Privileges []string `json:"privileges"`
}

// KibanaGrant is one Kibana privilege block of a role body.
type KibanaGrant struct {
	Base    []string       `json:"base"`
	Feature map[string]any `json:"feature"`
	Spaces  []string       `json:"spaces"`
}

// RoleBody is the body of PUT /api/security/role/<name>, limited to the
// fields the proxy owns.
type RoleBody struct {
	Elasticsearch struct {
		Cluster []string         `json:"cluster"`
		Indices []IndexPrivilege `json:"indices"`
	} `json:"elasticsearch"`
	Kibana []KibanaGrant `json:"kibana"`
}

// Role is a desired Kibana role.
type Role struct {
	Name string
	Body RoleBody
}

// Space is a desired Kibana space.
type Space struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Roles returns one role per declared level. The index grant is capped at
// read + view_index_metadata on the team's indices: never above the ACL.
func (c *Config) Roles() []Role {
	var out []Role
	for _, t := range c.teams {
		for _, l := range levelOrder {
			if _, ok := t.Levels[string(l)]; !ok {
				continue
			}
			var b RoleBody
			b.Elasticsearch.Cluster = []string{}
			b.Elasticsearch.Indices = []IndexPrivilege{{
				Names:      append([]string(nil), t.Indices...),
				Privileges: []string{"read", "view_index_metadata"},
			}}
			b.Kibana = []KibanaGrant{{
				Base: []string{KibanaBase(l)}, Feature: map[string]any{}, Spaces: []string{t.Space},
			}}
			out = append(out, Role{Name: RoleName(t.Name, l), Body: b})
		}
	}
	return out
}

// Spaces returns one space per team.
func (c *Config) Spaces() []Space {
	out := make([]Space, 0, len(c.teams))
	for _, t := range c.teams {
		out = append(out, Space{ID: t.Space, Name: t.Name})
	}
	return out
}
