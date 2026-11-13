package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	stdsync "sync"
	"testing"

	"proxy/internal/audit"
	"proxy/internal/teams"
)

// fakeKibana stores spaces and roles; it records every write.
type fakeKibana struct {
	mu     stdsync.Mutex
	spaces map[string]json.RawMessage
	roles  map[string]json.RawMessage
	writes int
}

func (f *fakeKibana) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, p, ok := r.BasicAuth(); !ok || u != "sync" || p != "pw" || r.Header.Get("kbn-xsrf") == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var body json.RawMessage
	if r.Method != http.MethodGet {
		f.writes++
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	switch {
	case r.URL.Path == "/api/spaces/space" && r.Method == http.MethodPost:
		var s teams.Space
		_ = json.Unmarshal(body, &s)
		f.spaces[s.ID] = body
	case strings.HasPrefix(r.URL.Path, "/api/spaces/space/"):
		id := strings.TrimPrefix(r.URL.Path, "/api/spaces/space/")
		if r.Method == http.MethodPut {
			f.spaces[id] = body
		} else if b, ok := f.spaces[id]; ok {
			w.Write(b)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	case strings.HasPrefix(r.URL.Path, "/api/security/role/"):
		n := strings.TrimPrefix(r.URL.Path, "/api/security/role/")
		if r.Method == http.MethodPut {
			f.roles[n] = body
		} else if b, ok := f.roles[n]; ok {
			w.Write(b)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func setup(t *testing.T) (*Syncer, *fakeKibana, *bytes.Buffer) {
	t.Helper()
	tc, err := teams.Parse([]teams.Team{{Name: "a", Space: "a", Indices: []string{"a-*"},
		Levels: map[string][]string{"viewer": {"v"}, "editor": {"e"}}}})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeKibana{spaces: map[string]json.RawMessage{}, roles: map[string]json.RawMessage{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	var buf bytes.Buffer
	return &Syncer{BaseURL: srv.URL, User: "sync", Password: "pw", Teams: tc, Audit: audit.New(&buf, nil)}, f, &buf
}

func TestApplyTwiceWritesOnce(t *testing.T) {
	s, f, _ := setup(t)
	ctx := context.Background()
	if _, err := s.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if f.writes != 3 { // 1 space + 2 roles
		t.Fatalf("first run writes = %d", f.writes)
	}
	plan, err := s.Apply(ctx)
	if err != nil || len(plan) != 0 || f.writes != 3 {
		t.Fatalf("second run: plan=%v err=%v writes=%d", plan, err, f.writes)
	}
}

func TestDriftRepairedAndAudited(t *testing.T) {
	s, f, buf := setup(t)
	ctx := context.Background()
	if _, err := s.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	f.roles["a_viewer"] = json.RawMessage(`{"metadata":{"x":1},"elasticsearch":{"cluster":[],"indices":[{"names":["a-*"],"privileges":["read","write","view_index_metadata"],"allow_restricted_indices":false}]},"kibana":[{"base":["read"],"feature":{},"spaces":["a"]}]}`)
	before, buf2 := f.writes, buf
	buf2.Reset()

	// dry-run: reports, writes nothing
	plan, err := s.Plan(ctx)
	if err != nil || len(plan) != 1 || plan[0].Kind != "update" || f.writes != before {
		t.Fatalf("plan=%v err=%v writes=%d", plan, err, f.writes)
	}

	if _, err := s.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if f.writes != before+1 {
		t.Fatalf("writes = %d", f.writes)
	}
	line := buf.String()
	if !strings.Contains(line, `"source":"sync"`) || !strings.Contains(line, "write") ||
		!strings.Contains(line, "/api/security/role/a_viewer") {
		t.Fatalf("audit line: %s", line)
	}
	if plan, _ := s.Apply(ctx); len(plan) != 0 || f.writes != before+1 {
		t.Fatalf("third run wrote: %v", plan)
	}
}

func TestApplyStopsOnHTTPError(t *testing.T) {
	s, _, _ := setup(t)
	s.Password = "bad"
	if _, err := s.Apply(context.Background()); err == nil {
		t.Fatal("want error")
	}
}
