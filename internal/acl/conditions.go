package acl

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// DecideContext carries the request properties a rule's optional
// conditions (F21) check against. RemoteAddr is the connection's real
// network address ("host:port" or a bare IP) — never a client-supplied
// header like X-Forwarded-For, which would be forgeable. Time is the
// clock Decide should use; tests inject a fixed value instead of
// time.Now().
type DecideContext struct {
	RemoteAddr string
	Method     string
	Time       time.Time
}

// matchesConditions reports whether ctx satisfies every condition set on
// r. A condition r doesn't set always matches (same behavior as before
// this ticket).
func (r compiledRule) matchesConditions(ctx DecideContext) bool {
	if len(r.sourceNets) > 0 {
		ip := net.ParseIP(hostOnly(ctx.RemoteAddr))
		if ip == nil {
			return false
		}
		matched := false
		for _, n := range r.sourceNets {
			if n.Contains(ip) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if r.methods != nil {
		if _, ok := r.methods[strings.ToUpper(ctx.Method)]; !ok {
			return false
		}
	}
	if r.timeWindow != nil {
		if ctx.Time.IsZero() || !r.timeWindow.matches(ctx.Time) {
			return false
		}
	}
	return true
}

// hostOnly strips a ":port" suffix from addr (the shape http.Request's
// RemoteAddr takes); a bare IP is returned unchanged.
func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// parseIPOrCIDR parses s as a CIDR, or as a bare IP treated as a /32 (or
// /128 for IPv6) network.
func parseIPOrCIDR(s string) (*net.IPNet, error) {
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		return ipnet, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("not an IP or CIDR")
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}

// compiledTimeWindow is a validated TimeWindow, minutes-since-midnight UTC.
type compiledTimeWindow struct {
	fromMinutes int
	toMinutes   int
	days        map[time.Weekday]struct{} // nil = every day
}

var weekdayNames = map[string]time.Weekday{
	"Sun": time.Sunday, "Mon": time.Monday, "Tue": time.Tuesday, "Wed": time.Wednesday,
	"Thu": time.Thursday, "Fri": time.Friday, "Sat": time.Saturday,
}

func compileTimeWindow(w TimeWindow) (*compiledTimeWindow, error) {
	from, err := parseHHMM(w.From)
	if err != nil {
		return nil, fmt.Errorf("time.from: %w", err)
	}
	to, err := parseHHMM(w.To)
	if err != nil {
		return nil, fmt.Errorf("time.to: %w", err)
	}
	var days map[time.Weekday]struct{}
	if len(w.Days) > 0 {
		days = make(map[time.Weekday]struct{}, len(w.Days))
		for _, d := range w.Days {
			wd, ok := weekdayNames[d]
			if !ok {
				return nil, fmt.Errorf("time.days: invalid day %q", d)
			}
			days[wd] = struct{}{}
		}
	}
	return &compiledTimeWindow{fromMinutes: from, toMinutes: to, days: days}, nil
}

func parseHHMM(s string) (int, error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, fmt.Errorf("must be HH:MM: %w", err)
	}
	return t.Hour()*60 + t.Minute(), nil
}

// matches reports whether t (converted to UTC) falls in the window.
// fromMinutes > toMinutes means the window wraps past midnight.
func (tw *compiledTimeWindow) matches(t time.Time) bool {
	t = t.UTC()
	if tw.days != nil {
		if _, ok := tw.days[t.Weekday()]; !ok {
			return false
		}
	}
	minutes := t.Hour()*60 + t.Minute()
	if tw.fromMinutes <= tw.toMinutes {
		return minutes >= tw.fromMinutes && minutes < tw.toMinutes
	}
	return minutes >= tw.fromMinutes || minutes < tw.toMinutes
}
