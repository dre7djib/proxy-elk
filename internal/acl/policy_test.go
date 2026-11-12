package acl

import "testing"

func validRule() Rule {
	return Rule{
		Name:    "r1",
		Groups:  []string{"team-a"},
		Indices: []string{"logs-*"},
		Actions: []string{"read"},
	}
}

func TestParseRejectsEmptyRules(t *testing.T) {
	if _, err := Parse(nil, nil, nil); err == nil {
		t.Fatal("expected error for empty rules")
	}
}

func TestParseRejectsWriteAction(t *testing.T) {
	r := validRule()
	r.Actions = []string{"write"}
	if _, err := Parse([]Rule{r}, nil, nil); err == nil {
		t.Fatal("expected error for write action")
	}
}

func TestParseRejectsRuleWithoutUsersOrGroups(t *testing.T) {
	r := validRule()
	r.Groups = nil
	if _, err := Parse([]Rule{r}, nil, nil); err == nil {
		t.Fatal("expected error for rule without users or groups")
	}
}

func TestParseRejectsRuleWithoutIndices(t *testing.T) {
	r := validRule()
	r.Indices = nil
	if _, err := Parse([]Rule{r}, nil, nil); err == nil {
		t.Fatal("expected error for rule without indices")
	}
}

func TestParseRejectsRuleWithoutActions(t *testing.T) {
	r := validRule()
	r.Actions = nil
	if _, err := Parse([]Rule{r}, nil, nil); err == nil {
		t.Fatal("expected error for rule without actions")
	}
}

func TestParseRejectsDuplicateRuleNames(t *testing.T) {
	r1, r2 := validRule(), validRule()
	if _, err := Parse([]Rule{r1, r2}, nil, nil); err == nil {
		t.Fatal("expected error for duplicate rule names")
	}
}

func TestParseRejectsUnknownGroup(t *testing.T) {
	r := validRule()
	r.Groups = []string{"team-b"}
	if _, err := Parse([]Rule{r}, []string{"team-a"}, nil); err == nil {
		t.Fatal("expected error for unknown group")
	}
}

func TestParseAllowsKnownGroup(t *testing.T) {
	r := validRule()
	if _, err := Parse([]Rule{r}, []string{"team-a"}, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRejectsBadPattern(t *testing.T) {
	r := validRule()
	r.Indices = []string{"["}
	if _, err := Parse([]Rule{r}, nil, nil); err == nil {
		t.Fatal("expected error for invalid index pattern")
	}
}
