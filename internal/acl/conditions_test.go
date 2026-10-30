package acl

import (
	"testing"
	"time"

	"proxy/internal/auth"
)

func ruleWithConditions(r Rule) Rule {
	r.Name = "r1"
	r.Groups = []string{"team-a"}
	r.Indices = []string{"logs-*"}
	r.Actions = []string{"read"}
	return r
}

var bob = auth.Identity{Subject: "bob", Groups: []string{"team-a"}}

func TestParseRejectsInvalidSourceIP(t *testing.T) {
	r := ruleWithConditions(Rule{SourceIPs: []string{"not-an-ip"}})
	if _, err := Parse([]Rule{r}, nil, nil); err == nil {
		t.Fatal("expected error for invalid source_ips entry")
	}
}

func TestParseRejectsInvalidTimeWindow(t *testing.T) {
	r := ruleWithConditions(Rule{Time: &TimeWindow{From: "nope", To: "18:00"}})
	if _, err := Parse([]Rule{r}, nil, nil); err == nil {
		t.Fatal("expected error for invalid time.from")
	}
}

func TestParseRejectsInvalidDay(t *testing.T) {
	r := ruleWithConditions(Rule{Time: &TimeWindow{From: "08:00", To: "18:00", Days: []string{"Funday"}}})
	if _, err := Parse([]Rule{r}, nil, nil); err == nil {
		t.Fatal("expected error for invalid day name")
	}
}

func TestDecideSourceIPCondition(t *testing.T) {
	r := ruleWithConditions(Rule{SourceIPs: []string{"10.0.0.0/8"}})
	p, err := Parse([]Rule{r}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Decide(bob, DecideContext{RemoteAddr: "10.1.2.3:4444"}, []string{"logs-1"}, ActionRead); err != nil {
		t.Fatalf("10.1.2.3 should be in 10.0.0.0/8: %v", err)
	}
	if err := p.Decide(bob, DecideContext{RemoteAddr: "192.168.1.1:4444"}, []string{"logs-1"}, ActionRead); err == nil {
		t.Fatal("192.168.1.1 should not match 10.0.0.0/8")
	}
	if err := p.Decide(bob, DecideContext{}, []string{"logs-1"}, ActionRead); err == nil {
		t.Fatal("no RemoteAddr should not satisfy a source_ips condition")
	}
}

func TestDecideBareIPSourceCondition(t *testing.T) {
	r := ruleWithConditions(Rule{SourceIPs: []string{"203.0.113.5"}})
	p, err := Parse([]Rule{r}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Decide(bob, DecideContext{RemoteAddr: "203.0.113.5:9999"}, []string{"logs-1"}, ActionRead); err != nil {
		t.Fatalf("exact IP should match: %v", err)
	}
	if err := p.Decide(bob, DecideContext{RemoteAddr: "203.0.113.6:9999"}, []string{"logs-1"}, ActionRead); err == nil {
		t.Fatal("different IP should not match a bare-IP condition")
	}
}

func TestDecideMethodsCondition(t *testing.T) {
	r := ruleWithConditions(Rule{Methods: []string{"GET", "POST"}})
	p, err := Parse([]Rule{r}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Decide(bob, DecideContext{Method: "GET"}, []string{"logs-1"}, ActionRead); err != nil {
		t.Fatalf("GET should be allowed: %v", err)
	}
	if err := p.Decide(bob, DecideContext{Method: "DELETE"}, []string{"logs-1"}, ActionRead); err == nil {
		t.Fatal("DELETE should not match methods: [GET, POST]")
	}
}

func TestDecideTimeWindowCondition(t *testing.T) {
	r := ruleWithConditions(Rule{Time: &TimeWindow{
		From: "08:00", To: "18:00", Days: []string{"Mon", "Tue", "Wed", "Thu", "Fri"},
	}})
	p, err := Parse([]Rule{r}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	inside := time.Date(2024, 1, 8, 12, 0, 0, 0, time.UTC) // Monday
	if err := p.Decide(bob, DecideContext{Time: inside}, []string{"logs-1"}, ActionRead); err != nil {
		t.Fatalf("Monday noon UTC should be inside the window: %v", err)
	}

	outsideHour := time.Date(2024, 1, 8, 20, 0, 0, 0, time.UTC) // Monday, 20:00
	if err := p.Decide(bob, DecideContext{Time: outsideHour}, []string{"logs-1"}, ActionRead); err == nil {
		t.Fatal("20:00 should be outside the 08:00-18:00 window")
	}

	weekend := time.Date(2024, 1, 6, 12, 0, 0, 0, time.UTC) // Saturday
	if err := p.Decide(bob, DecideContext{Time: weekend}, []string{"logs-1"}, ActionRead); err == nil {
		t.Fatal("Saturday should be outside the Mon-Fri window")
	}

	if err := p.Decide(bob, DecideContext{}, []string{"logs-1"}, ActionRead); err == nil {
		t.Fatal("zero Time should not satisfy a time condition")
	}
}

func TestDecideTimeWindowWrapsPastMidnight(t *testing.T) {
	r := ruleWithConditions(Rule{Time: &TimeWindow{From: "22:00", To: "06:00"}})
	p, err := Parse([]Rule{r}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	lateNight := time.Date(2024, 1, 8, 23, 0, 0, 0, time.UTC)
	if err := p.Decide(bob, DecideContext{Time: lateNight}, []string{"logs-1"}, ActionRead); err != nil {
		t.Fatalf("23:00 should be inside a 22:00-06:00 window: %v", err)
	}
	earlyMorning := time.Date(2024, 1, 9, 3, 0, 0, 0, time.UTC)
	if err := p.Decide(bob, DecideContext{Time: earlyMorning}, []string{"logs-1"}, ActionRead); err != nil {
		t.Fatalf("03:00 should be inside a 22:00-06:00 window: %v", err)
	}
	midday := time.Date(2024, 1, 9, 12, 0, 0, 0, time.UTC)
	if err := p.Decide(bob, DecideContext{Time: midday}, []string{"logs-1"}, ActionRead); err == nil {
		t.Fatal("noon should be outside a 22:00-06:00 window")
	}
}

func TestDecideAbsentConditionsBehaveAsBefore(t *testing.T) {
	r := ruleWithConditions(Rule{})
	p, err := Parse([]Rule{r}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Decide(bob, DecideContext{}, []string{"logs-1"}, ActionRead); err != nil {
		t.Fatalf("rule without conditions should match regardless of ctx: %v", err)
	}
}
