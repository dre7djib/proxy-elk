package auth

import (
	"testing"
	"time"
)

func newTestLimiter(t *testing.T) (*Limiter, *fakeClock) {
	t.Helper()
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	lm := NewLimiter(LockoutConfig{MaxFailures: 3, FailureWindow: 15 * time.Minute, LockoutFor: 15 * time.Minute})
	lm.now = clock.Now
	return lm, clock
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestLimiterLocksAfterMaxFailures(t *testing.T) {
	lm, _ := newTestLimiter(t)
	for i := 0; i < 2; i++ {
		lm.Fail("alice", "10.0.0.1")
		if !lm.Allow("alice", "10.0.0.1") {
			t.Fatalf("locked out after only %d failures", i+1)
		}
	}
	lm.Fail("alice", "10.0.0.1")
	if lm.Allow("alice", "10.0.0.1") {
		t.Fatal("expected lockout after 3 failures")
	}
}

func TestLimiterUnlocksAfterLockoutFor(t *testing.T) {
	lm, clock := newTestLimiter(t)
	for i := 0; i < 3; i++ {
		lm.Fail("alice", "10.0.0.1")
	}
	if lm.Allow("alice", "10.0.0.1") {
		t.Fatal("expected lockout")
	}
	clock.advance(15*time.Minute + time.Second)
	if !lm.Allow("alice", "10.0.0.1") {
		t.Fatal("expected unlock after lockout_for elapsed")
	}
}

func TestLimiterSuccessResets(t *testing.T) {
	lm, _ := newTestLimiter(t)
	lm.Fail("alice", "10.0.0.1")
	lm.Fail("alice", "10.0.0.1")
	lm.Success("alice", "10.0.0.1")
	lm.Fail("alice", "10.0.0.1")
	if !lm.Allow("alice", "10.0.0.1") {
		t.Fatal("success should have reset the failure count")
	}
}

func TestLimiterKeysAreIndependentPerIP(t *testing.T) {
	lm, _ := newTestLimiter(t)
	for i := 0; i < 3; i++ {
		lm.Fail("alice", "10.0.0.1")
	}
	if !lm.Allow("alice", "10.0.0.2") {
		t.Fatal("a different IP for the same user must not be locked out")
	}
	if lm.Allow("alice", "10.0.0.1") {
		t.Fatal("the original IP should still be locked out")
	}
}

func TestLimiterKeysAreIndependentPerUser(t *testing.T) {
	lm, _ := newTestLimiter(t)
	for i := 0; i < 3; i++ {
		lm.Fail("alice", "10.0.0.1")
	}
	if !lm.Allow("bob", "10.0.0.1") {
		t.Fatal("a different user from the same IP must not be locked out")
	}
}

func TestLimiterFailureWindowResets(t *testing.T) {
	lm, clock := newTestLimiter(t)
	lm.Fail("alice", "10.0.0.1")
	lm.Fail("alice", "10.0.0.1")
	clock.advance(15*time.Minute + time.Second)
	// Window elapsed: this should start a fresh window, not reach MaxFailures.
	lm.Fail("alice", "10.0.0.1")
	if !lm.Allow("alice", "10.0.0.1") {
		t.Fatal("failure window should have reset the count")
	}
}

func TestLimiterDisabledWhenMaxFailuresZero(t *testing.T) {
	lm := NewLimiter(LockoutConfig{})
	for i := 0; i < 100; i++ {
		lm.Fail("alice", "10.0.0.1")
	}
	if !lm.Allow("alice", "10.0.0.1") {
		t.Fatal("MaxFailures 0 must disable lockout")
	}
}

func TestNilLimiterAlwaysAllows(t *testing.T) {
	var lm *Limiter
	lm.Fail("alice", "10.0.0.1")
	lm.Success("alice", "10.0.0.1")
	if !lm.Allow("alice", "10.0.0.1") {
		t.Fatal("nil limiter must always allow")
	}
}
