package acl

import (
	"path"
	"strings"
)

// isSystemIndex reports whether index is a system index (F17): names
// starting with "." or matching a configured system pattern.
func isSystemIndex(index string, systemIndices []string) bool {
	if strings.HasPrefix(index, ".") {
		return true
	}
	for _, p := range systemIndices {
		if ok, _ := path.Match(p, index); ok {
			return true
		}
	}
	return false
}

// patternIsSystem reports whether pattern is itself a "system" pattern:
// starting with "." or equal to a configured system pattern. Only such a
// pattern may grant access to a system index (F17) — a generic wildcard
// like "*" or "logs-*" never does, however broad.
func patternIsSystem(pattern string, systemIndices []string) bool {
	if strings.HasPrefix(pattern, ".") {
		return true
	}
	for _, p := range systemIndices {
		if pattern == p {
			return true
		}
	}
	return false
}

// indexMatches reports whether pattern grants access to index, honoring
// the F17 system-index gate: a match against a system index only counts if
// pattern is itself a system pattern.
func indexMatches(pattern, index string, systemIndices []string) bool {
	matched, err := path.Match(pattern, index)
	if err != nil || !matched {
		return false
	}
	if isSystemIndex(index, systemIndices) {
		return patternIsSystem(pattern, systemIndices)
	}
	return true
}
