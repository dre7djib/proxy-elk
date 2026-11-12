package limits

import (
	"sync"
	"time"
)

type windowState struct {
	count     int
	windowEnd time.Time
}

// Counter tracks requests per minute per subject (not per group, so one
// caller can't exhaust the quota shared by the rest of their group — see
// the plan's "Comportement" section). Fixed one-minute windows, in
// memory, clock injected for tests.
//
// shortcut: entries are never pruned; fine at MVP scale (one process, no
// persistence across restarts), revisit with a TTL store if memory
// growth matters — same shortcut as auth.Limiter.
type Counter struct {
	mu    sync.Mutex
	state map[string]*windowState
	now   func() time.Time
}

// NewCounter returns a Counter using time.Now as its clock.
func NewCounter() *Counter {
	return &Counter{state: make(map[string]*windowState), now: time.Now}
}

// Allow records one request for subject and reports whether it is within
// limit requests in the current one-minute window. A nil *Counter always
// allows.
func (c *Counter) Allow(subject string, limit int) bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	st, ok := c.state[subject]
	if !ok || !now.Before(st.windowEnd) {
		st = &windowState{windowEnd: now.Add(time.Minute)}
		c.state[subject] = st
	}
	st.count++
	return st.count <= limit
}
