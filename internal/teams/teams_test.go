package teams

import (
	"reflect"
	"strings"
	"testing"
)

func two() []Team {
	return []Team{
		{Name: "a", Space: "a", Indices: []string{"a-*"}, Levels: map[string][]string{
			"viewer": {"a-v"}, "editor": {"a-e"}}},
		{Name: "b", Space: "b", Indices: []string{"b-*"}, Levels: map[string][]string{
			"admin": {"b-adm"}}},
	}
}

func TestMemberships(t *testing.T) {
	c, err := Parse(two())
	if err != nil {
		t.Fatal(err)
	}
	got := c.Memberships([]string{"b-adm", "a-v", "a-e"})
	want := []Membership{{"a", Viewer, "a"}, {"a", Editor, "a"}, {"b", Admin, "b"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if m := c.Memberships([]string{"unknown"}); len(m) != 0 {
		t.Fatalf("unknown group: %v", m)
	}
	r := c.Rules()
	if len(r) != 2 || r[0].Name != "team:a" || !reflect.DeepEqual(r[0].Groups, []string{"a-v", "a-e"}) {
		t.Fatalf("rules: %+v", r)
	}
	if RoleName("a", Viewer) != "a_viewer" || KibanaBase(Viewer) != "read" || KibanaBase(Admin) != "all" {
		t.Fatal("role name / kibana base")
	}
}

func TestParseRejects(t *testing.T) {
	mut := func(f func(*Team)) []Team {
		ts := two()
		f(&ts[0])
		return ts
	}
	cases := map[string][]Team{
		"empty name":    mut(func(t *Team) { t.Name = "" }),
		"bad charset":   mut(func(t *Team) { t.Name = "A b" }),
		"empty space":   mut(func(t *Team) { t.Space = "" }),
		"dup space":     mut(func(t *Team) { t.Space = "b" }),
		"dup name":      mut(func(t *Team) { t.Name = "b" }),
		"no indices":    mut(func(t *Team) { t.Indices = nil }),
		"system index":  mut(func(t *Team) { t.Indices = []string{".security*"} }),
		"bad glob":      mut(func(t *Team) { t.Indices = []string{"[a"} }),
		"unknown level": mut(func(t *Team) { t.Levels = map[string][]string{"root": {"g"}} }),
		"empty level":   mut(func(t *Team) { t.Levels = map[string][]string{"viewer": nil} }),
		"dup in team":   mut(func(t *Team) { t.Levels = map[string][]string{"viewer": {"g"}, "editor": {"g"}} }),
		"dup across":    mut(func(t *Team) { t.Levels = map[string][]string{"viewer": {"b-adm"}} }),
	}
	for name, ts := range cases {
		if _, err := Parse(ts); err == nil || !strings.HasPrefix(err.Error(), "teams:") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestRolesCapped(t *testing.T) {
	c, _ := Parse(two())
	roles := c.Roles()
	if len(roles) != 3 {
		t.Fatalf("roles: %d", len(roles))
	}
	for _, r := range roles {
		ix := r.Body.Elasticsearch.Indices
		if len(r.Body.Elasticsearch.Cluster) != 0 || len(ix) != 1 ||
			!reflect.DeepEqual(ix[0].Privileges, []string{"read", "view_index_metadata"}) {
			t.Fatalf("%s: not capped: %+v", r.Name, r.Body)
		}
	}
	if roles[0].Name != "a_viewer" || roles[0].Body.Kibana[0].Base[0] != "read" ||
		roles[1].Body.Kibana[0].Base[0] != "all" || roles[2].Body.Kibana[0].Spaces[0] != "b" {
		t.Fatalf("roles: %+v", roles)
	}
	if s := c.Spaces(); len(s) != 2 || s[0].ID != "a" || s[0].Name != "a" {
		t.Fatalf("spaces: %v", s)
	}
}
