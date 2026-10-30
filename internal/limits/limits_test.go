package limits

import (
	"testing"
	"time"

	"proxy/internal/auth"
)

func TestParseRejectsBadDuration(t *testing.T) {
	r := Role{Groups: []string{"team-a"}, MaxDuration: "nope", MaxResultBytes: 1, RequestsPerMinute: 1}
	if _, err := Parse(nil, []Role{r}, nil); err == nil {
		t.Fatal("expected error for invalid max_duration")
	}
}

func TestParseRejectsZeroQuota(t *testing.T) {
	r := Role{Groups: []string{"team-a"}, MaxDuration: "1s", MaxResultBytes: 0, RequestsPerMinute: 1}
	if _, err := Parse(nil, []Role{r}, nil); err == nil {
		t.Fatal("expected error for max_result_bytes = 0")
	}
	r2 := Role{Groups: []string{"team-a"}, MaxDuration: "1s", MaxResultBytes: 1, RequestsPerMinute: 0}
	if _, err := Parse(nil, []Role{r2}, nil); err == nil {
		t.Fatal("expected error for requests_per_minute = 0")
	}
}

func TestParseRejectsGroupInTwoEntries(t *testing.T) {
	r1 := Role{Groups: []string{"team-a"}, MaxDuration: "1s", MaxResultBytes: 1, RequestsPerMinute: 1}
	r2 := Role{Groups: []string{"team-a"}, MaxDuration: "2s", MaxResultBytes: 2, RequestsPerMinute: 2}
	if _, err := Parse(nil, []Role{r1, r2}, nil); err == nil {
		t.Fatal("expected error for group used in two entries")
	}
}

func TestParseRejectsUnknownGroup(t *testing.T) {
	r := Role{Groups: []string{"team-b"}, MaxDuration: "1s", MaxResultBytes: 1, RequestsPerMinute: 1}
	if _, err := Parse(nil, []Role{r}, []string{"team-a"}); err == nil {
		t.Fatal("expected error for unknown group")
	}
}

func TestResolveReturnsDefaultWhenNoRoleMatches(t *testing.T) {
	def := Role{MaxDuration: "30s", MaxResultBytes: 100, RequestsPerMinute: 10}
	l, err := Parse(&def, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	q := l.Resolve(auth.Identity{Subject: "bob", Groups: []string{"team-a"}})
	if q == nil || q.RequestsPerMinute != 10 {
		t.Fatalf("quota = %+v", q)
	}
}

func TestResolveUnlimitedWhenNothingMatches(t *testing.T) {
	l, err := Parse(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if q := l.Resolve(auth.Identity{Subject: "bob"}); q != nil {
		t.Fatalf("expected unlimited, got %+v", q)
	}
}

func TestResolveTakesMinimumOfMatchingGroups(t *testing.T) {
	r1 := Role{Groups: []string{"team-a"}, MaxDuration: "30s", MaxResultBytes: 1000, RequestsPerMinute: 100}
	r2 := Role{Groups: []string{"team-b"}, MaxDuration: "10s", MaxResultBytes: 2000, RequestsPerMinute: 50}
	l, err := Parse(nil, []Role{r1, r2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	q := l.Resolve(auth.Identity{Subject: "bob", Groups: []string{"team-a", "team-b"}})
	if q == nil {
		t.Fatal("expected a quota")
	}
	if q.MaxDuration != 10*time.Second {
		t.Fatalf("max duration = %v, want 10s (min)", q.MaxDuration)
	}
	if q.MaxResultBytes != 1000 {
		t.Fatalf("max result bytes = %d, want 1000 (min)", q.MaxResultBytes)
	}
	if q.RequestsPerMinute != 50 {
		t.Fatalf("requests per minute = %d, want 50 (min)", q.RequestsPerMinute)
	}
}

func TestResolveNilLimitsIsUnlimited(t *testing.T) {
	var l *Limits
	if q := l.Resolve(auth.Identity{Subject: "bob"}); q != nil {
		t.Fatalf("expected unlimited, got %+v", q)
	}
}
