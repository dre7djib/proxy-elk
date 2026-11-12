package limits

import (
	"testing"
	"time"
)

func TestCounterAllowsUpToLimitThenRefuses(t *testing.T) {
	c := NewCounter()
	for i := 0; i < 3; i++ {
		if !c.Allow("bob", 3) {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	if c.Allow("bob", 3) {
		t.Fatal("4th request should be refused")
	}
}

func TestCounterResetsOnNextWindow(t *testing.T) {
	c := NewCounter()
	now := time.Now()
	c.now = func() time.Time { return now }

	if !c.Allow("bob", 1) {
		t.Fatal("first request should be allowed")
	}
	if c.Allow("bob", 1) {
		t.Fatal("second request in same window should be refused")
	}

	now = now.Add(time.Minute)
	if !c.Allow("bob", 1) {
		t.Fatal("request in next window should be allowed")
	}
}

func TestCounterIsPerSubject(t *testing.T) {
	c := NewCounter()
	if !c.Allow("alice", 1) {
		t.Fatal("alice's first request should be allowed")
	}
	if !c.Allow("bob", 1) {
		t.Fatal("bob's quota is independent of alice's")
	}
}
