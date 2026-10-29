package auth

import (
	"strings"
	"sync"
	"time"
)

// LockoutConfig configures a Limiter. MaxFailures <= 0 disables lockout
// entirely (Allow always true).
type LockoutConfig struct {
	MaxFailures   int
	FailureWindow time.Duration
	LockoutFor    time.Duration
}

type lockoutState struct {
	failures    int
	windowEnd   time.Time
	lockedUntil time.Time
}

// Limiter blocks login attempts for a (username, IP) pair after too many
// failures within a sliding window (F8). A nil *Limiter always allows and
// never panics, so it is safe to leave unset.
//
// shortcut: entries are never pruned except by Success or a new window
// starting; fine at MVP scale (one process, no persistence across
// restarts), revisit with a TTL store if memory growth matters.
type Limiter struct {
	cfg   LockoutConfig
	mu    sync.Mutex
	state map[string]*lockoutState
	now   func() time.Time
}

// NewLimiter returns a Limiter enforcing cfg.
func NewLimiter(cfg LockoutConfig) *Limiter {
	return &Limiter{cfg: cfg, state: make(map[string]*lockoutState), now: time.Now}
}

func lockoutKey(username, ip string) string {
	return strings.ToLower(username) + "|" + ip
}

// Allow reports whether username from ip may attempt a login right now.
func (lm *Limiter) Allow(username, ip string) bool {
	if lm == nil || lm.cfg.MaxFailures <= 0 {
		return true
	}
	lm.mu.Lock()
	defer lm.mu.Unlock()
	st, ok := lm.state[lockoutKey(username, ip)]
	if !ok {
		return true
	}
	return lm.now().After(st.lockedUntil)
}

// Fail records a failed login attempt for username from ip, locking out the
// pair for LockoutFor once MaxFailures is reached within FailureWindow.
func (lm *Limiter) Fail(username, ip string) {
	if lm == nil || lm.cfg.MaxFailures <= 0 {
		return
	}
	lm.mu.Lock()
	defer lm.mu.Unlock()

	key := lockoutKey(username, ip)
	now := lm.now()
	st, ok := lm.state[key]
	if !ok || now.After(st.windowEnd) {
		st = &lockoutState{windowEnd: now.Add(lm.cfg.FailureWindow)}
		lm.state[key] = st
	}
	st.failures++
	if st.failures >= lm.cfg.MaxFailures {
		st.lockedUntil = now.Add(lm.cfg.LockoutFor)
	}
}

// Success resets the failure count for username from ip.
func (lm *Limiter) Success(username, ip string) {
	if lm == nil {
		return
	}
	lm.mu.Lock()
	defer lm.mu.Unlock()
	delete(lm.state, lockoutKey(username, ip))
}
