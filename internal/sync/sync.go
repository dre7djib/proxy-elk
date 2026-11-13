// Package sync pushes the YAML teams to Kibana: one space per team and
// one role per level, through Kibana's own APIs. It compares before it
// writes, so a second run changes nothing.
package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"time"

	"proxy/internal/audit"
	"proxy/internal/teams"
)

// Syncer talks to Kibana at BaseURL with Basic auth.
type Syncer struct {
	BaseURL  string
	User     string
	Password string
	Client   *http.Client
	Audit    *audit.Logger // may be nil
	Teams    *teams.Config
}

// Action is one planned write.
type Action struct {
	Kind   string // "create" or "update"
	Method string
	Path   string
	Reason string
	body   any
}

func (a Action) String() string { return fmt.Sprintf("%s %s (%s)", a.Kind, a.Path, a.Reason) }

// Plan reads Kibana and returns the writes needed. It never writes.
func (s *Syncer) Plan(ctx context.Context) ([]Action, error) {
	var out []Action
	for _, sp := range s.Teams.Spaces() {
		p := "/api/spaces/space/" + url.PathEscape(sp.ID)
		var have teams.Space
		found, err := s.get(ctx, p, &have)
		if err != nil {
			return nil, err
		}
		switch {
		case !found:
			out = append(out, Action{"create", http.MethodPost, "/api/spaces/space", "missing", sp})
			out[len(out)-1].Path = p // reported path; the POST goes to the collection
		case have.Name != sp.Name:
			out = append(out, Action{"update", http.MethodPut, p, fmt.Sprintf("remote name %q, want %q", have.Name, sp.Name), sp})
		}
	}
	for _, r := range s.Teams.Roles() {
		p := "/api/security/role/" + url.PathEscape(r.Name)
		var have teams.RoleBody
		found, err := s.get(ctx, p, &have)
		if err != nil {
			return nil, err
		}
		if !found {
			out = append(out, Action{"create", http.MethodPut, p, "missing", r.Body})
		} else if !sameRole(have, r.Body) {
			out = append(out, Action{"update", http.MethodPut, p, "remote grants " + describe(have), r.Body})
		}
	}
	return out, nil
}

// Apply plans, then audits and sends each write. It stops at the first
// HTTP error; a later run resumes from the remaining differences.
func (s *Syncer) Apply(ctx context.Context) ([]Action, error) {
	plan, err := s.Plan(ctx)
	if err != nil {
		return nil, err
	}
	for i, a := range plan {
		s.audit(a)
		target := a.Path
		if a.Kind == "create" && strings.HasPrefix(a.Path, "/api/spaces/space/") {
			target = "/api/spaces/space"
		}
		if err := s.send(ctx, a.Method, target, a.body); err != nil {
			return plan[:i], err
		}
	}
	return plan, nil
}

func (s *Syncer) audit(a Action) {
	if s.Audit == nil {
		return
	}
	s.Audit.Write(audit.Record{
		TS: time.Now().UTC().Format(time.RFC3339), Source: audit.SourceSync, User: s.User,
		Decision: audit.DecisionAllowed, Reason: a.Kind + ": " + a.Reason,
		HTTPMethod: a.Method, Path: a.Path,
	})
}

func (s *Syncer) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(s.BaseURL, "/")+path, rd)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(s.User, s.Password)
	req.Header.Set("kbn-xsrf", "true")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c := s.Client
	if c == nil {
		c = http.DefaultClient
	}
	return c.Do(req)
}

func (s *Syncer) get(ctx context.Context, path string, into any) (bool, error) {
	resp, err := s.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		return false, fmt.Errorf("GET %s: %w", path, err)
	}
	return true, nil
}

func (s *Syncer) send(ctx context.Context, method, path string, body any) error {
	resp, err := s.do(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	return nil
}

// sameRole compares owned fields only, ignoring order.
func sameRole(a, b teams.RoleBody) bool {
	return reflect.DeepEqual(norm(a), norm(b))
}

func norm(b teams.RoleBody) teams.RoleBody {
	out := teams.RoleBody{}
	out.Elasticsearch.Cluster = sorted(b.Elasticsearch.Cluster)
	for _, ix := range b.Elasticsearch.Indices {
		out.Elasticsearch.Indices = append(out.Elasticsearch.Indices,
			teams.IndexPrivilege{Names: sorted(ix.Names), Privileges: sorted(ix.Privileges)})
	}
	sort.Slice(out.Elasticsearch.Indices, func(i, j int) bool {
		return strings.Join(out.Elasticsearch.Indices[i].Names, ",") < strings.Join(out.Elasticsearch.Indices[j].Names, ",")
	})
	for _, k := range b.Kibana {
		f := k.Feature
		if len(f) == 0 {
			f = map[string]any{}
		}
		out.Kibana = append(out.Kibana, teams.KibanaGrant{Base: sorted(k.Base), Feature: f, Spaces: sorted(k.Spaces)})
	}
	return out
}

func sorted(s []string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}

func describe(b teams.RoleBody) string {
	j, _ := json.Marshal(norm(b))
	return string(j)
}
