// Package esql extracts the indices and ENRICH policies an ES|QL query
// reads, for fail-closed ACL checks (J2-08 / F27).
package esql

import (
	"strings"
	"unicode"
)

// Parsed is what a query reads. Uncertain means the text could not be
// classified safely — callers must deny (F38).
type Parsed struct {
	Indices   []string // FROM + LOOKUP JOIN targets
	Policies  []string // ENRICH policy names (not yet resolved to indices)
	Uncertain bool
}

// Parse extracts index and ENRICH policy names from an ES|QL query.
// It covers FROM, LOOKUP JOIN and ENRICH on Elasticsearch 8.19 (no FORK).
// Remote-cluster (cluster:index) references and unrecognised shapes set
// Uncertain.
func Parse(query string) Parsed {
	query = strings.TrimSpace(query)
	if query == "" {
		return Parsed{Uncertain: true}
	}
	cmds, ok := splitPipes(query)
	if !ok {
		return Parsed{Uncertain: true}
	}
	var out Parsed
	sawSource := false
	for i, cmd := range cmds {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			return Parsed{Uncertain: true}
		}
		kw, rest, ok := firstToken(cmd)
		if !ok {
			return Parsed{Uncertain: true}
		}
		switch strings.ToUpper(kw) {
		case "FROM":
			if i != 0 {
				return Parsed{Uncertain: true}
			}
			idxs, ok := parseFromSources(rest)
			if !ok {
				return Parsed{Uncertain: true}
			}
			out.Indices = append(out.Indices, idxs...)
			sawSource = true
		case "ROW", "SHOW":
			if i != 0 {
				return Parsed{Uncertain: true}
			}
			sawSource = true
		case "LOOKUP":
			idx, ok := parseLookupJoin(rest)
			if !ok {
				return Parsed{Uncertain: true}
			}
			out.Indices = append(out.Indices, idx)
		case "ENRICH":
			policy, ok := parseEnrich(rest)
			if !ok {
				return Parsed{Uncertain: true}
			}
			out.Policies = append(out.Policies, policy)
		case "FORK":
			return Parsed{Uncertain: true}
		default:
			if i == 0 {
				return Parsed{Uncertain: true}
			}
			// KEEP, WHERE, LIMIT, STATS, EVAL, SORT, … — no index refs.
		}
	}
	if !sawSource {
		return Parsed{Uncertain: true}
	}
	return out
}

func splitPipes(q string) ([]string, bool) {
	var parts []string
	var b strings.Builder
	inQuote := false
	escape := false
	for _, r := range q {
		if inQuote {
			b.WriteRune(r)
			if escape {
				escape = false
				continue
			}
			if r == '\\' {
				escape = true
				continue
			}
			if r == '"' {
				inQuote = false
			}
			continue
		}
		if r == '"' {
			inQuote = true
			b.WriteRune(r)
			continue
		}
		if r == '|' {
			parts = append(parts, b.String())
			b.Reset()
			continue
		}
		b.WriteRune(r)
	}
	if inQuote {
		return nil, false
	}
	parts = append(parts, b.String())
	return parts, true
}

func firstToken(s string) (tok, rest string, ok bool) {
	s = strings.TrimLeftFunc(s, unicode.IsSpace)
	if s == "" {
		return "", "", false
	}
	if s[0] == '"' {
		ident, rest, ok := readQuoted(s)
		return ident, rest, ok
	}
	i := 0
	for i < len(s) {
		r := rune(s[i])
		if unicode.IsSpace(r) || r == ',' || r == '|' {
			break
		}
		i++
	}
	return s[:i], strings.TrimLeftFunc(s[i:], unicode.IsSpace), true
}

func readQuoted(s string) (ident, rest string, ok bool) {
	if len(s) < 2 || s[0] != '"' {
		return "", "", false
	}
	var b strings.Builder
	escape := false
	for i := 1; i < len(s); i++ {
		c := s[i]
		if escape {
			b.WriteByte(c)
			escape = false
			continue
		}
		if c == '\\' {
			escape = true
			continue
		}
		if c == '"' {
			return b.String(), strings.TrimLeftFunc(s[i+1:], unicode.IsSpace), true
		}
		b.WriteByte(c)
	}
	return "", "", false
}

// parseFromSources reads the index list after FROM, stopping at METADATA.
func parseFromSources(rest string) ([]string, bool) {
	var indices []string
	s := strings.TrimSpace(rest)
	if s == "" {
		return nil, false
	}
	for s != "" {
		kw, _, _ := firstToken(s)
		if strings.EqualFold(kw, "METADATA") {
			break
		}
		ident, next, ok := readIndexIdent(s)
		if !ok || ident == "" {
			return nil, false
		}
		if strings.Contains(ident, ":") {
			// cluster:index (CCS) — not supported; fail closed.
			return nil, false
		}
		indices = append(indices, ident)
		s = next
		if s == "" {
			break
		}
		if strings.HasPrefix(s, ",") {
			s = strings.TrimLeftFunc(s[1:], unicode.IsSpace)
			if s == "" {
				return nil, false
			}
			continue
		}
		kw, _, _ = firstToken(s)
		if strings.EqualFold(kw, "METADATA") {
			break
		}
		// Trailing junk after the list.
		return nil, false
	}
	if len(indices) == 0 {
		return nil, false
	}
	return indices, true
}

func readIndexIdent(s string) (ident, rest string, ok bool) {
	s = strings.TrimLeftFunc(s, unicode.IsSpace)
	if s == "" {
		return "", "", false
	}
	if s[0] == '"' {
		return readQuoted(s)
	}
	i := 0
	for i < len(s) {
		c := s[i]
		if c == ',' || c == '|' || unicode.IsSpace(rune(c)) {
			break
		}
		i++
	}
	if i == 0 {
		return "", "", false
	}
	return s[:i], strings.TrimLeftFunc(s[i:], unicode.IsSpace), true
}

// parseLookupJoin expects "JOIN <index> ON ..." after the LOOKUP keyword.
func parseLookupJoin(rest string) (string, bool) {
	kw, rest, ok := firstToken(rest)
	if !ok || !strings.EqualFold(kw, "JOIN") {
		return "", false
	}
	ident, rest, ok := readIndexIdent(rest)
	if !ok || ident == "" || strings.Contains(ident, ":") {
		return "", false
	}
	on, _, ok := firstToken(rest)
	if !ok || !strings.EqualFold(on, "ON") {
		return "", false
	}
	return ident, true
}

// parseEnrich expects "<policy> ON ..." after ENRICH.
func parseEnrich(rest string) (string, bool) {
	ident, rest, ok := readIndexIdent(rest)
	if !ok || ident == "" {
		return "", false
	}
	on, _, ok := firstToken(rest)
	if !ok || !strings.EqualFold(on, "ON") {
		return "", false
	}
	return ident, true
}
