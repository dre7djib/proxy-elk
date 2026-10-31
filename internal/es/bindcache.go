package es

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"proxy/internal/auth"
)

// bindCache avoids an LDAP bind on every call: Kibana replays Basic auth
// on asCurrentUser dozens of times per page (login + Discover). Key is
// subject + password hash; the plaintext password is never stored.
type bindCache struct {
	mu      sync.Mutex
	entries map[string]bindEntry
}

type bindEntry struct {
	id     *auth.Identity
	expiry time.Time
}

func newBindCache() *bindCache {
	return &bindCache{entries: make(map[string]bindEntry)}
}

func bindCacheKey(user, password string) string {
	sum := sha256.Sum256([]byte(password))
	return user + "\x00" + hex.EncodeToString(sum[:])
}

func (c *bindCache) get(user, password string) (*auth.Identity, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := bindCacheKey(user, password)
	e, ok := c.entries[k]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expiry) {
		delete(c.entries, k)
		return nil, false
	}
	return e.id, true
}

func (c *bindCache) put(user, password string, id *auth.Identity, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[bindCacheKey(user, password)] = bindEntry{id: id, expiry: time.Now().Add(ttl)}
}
