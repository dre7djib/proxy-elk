package ask

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"proxy/internal/acl"
	"proxy/internal/audit"
	"proxy/internal/auth"
)

type testResolver struct{ all []string }

func (t testResolver) Resolve(_ context.Context, names []string) ([]string, error) {
	if len(names) == 1 && names[0] == "*" {
		return append([]string(nil), t.all...), nil
	}
	return append([]string(nil), names...), nil
}

type mapEnrich map[string][]string

func (m mapEnrich) SourceIndices(_ context.Context, policy string) ([]string, error) {
	idxs, ok := m[policy]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return idxs, nil
}

type fakes struct {
	h          *Handler
	modelCalls atomic.Int32
	queries    []string
	paths      []string
	modelBody  []string
	rowCount   int
}

// newFakes: each messages entry is one assistant message JSON, in order.
// /_query fails for every query containing "bad".
func newFakes(t *testing.T, messages ...string) *fakes {
	t.Helper()
	f := &fakes{}
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.paths = append(f.paths, r.URL.Path)
		switch {
		case strings.HasSuffix(r.URL.Path, "/_mapping"):
			w.Write([]byte(`{"equipe-a-sample":{"mappings":{"properties":{"message":{"type":"text"},"host":{"type":"keyword"}}}}}`))
		case r.URL.Path == "/_query":
			var q struct{ Query string }
			json.Unmarshal(b, &q)
			f.queries = append(f.queries, q.Query)
			if strings.Contains(q.Query, "bad") {
				w.WriteHeader(400)
				w.Write([]byte("Unknown column [bad]"))
				return
			}
			w.Write([]byte(f.valuesJSON()))
		default:
			t.Errorf("unexpected ES path %s", r.URL.Path)
		}
	}))
	t.Cleanup(es.Close)
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.modelBody = append(f.modelBody, string(b))
		i := int(f.modelCalls.Add(1)) - 1
		if i >= len(messages) {
			http.Error(w, "no more replies", http.StatusInternalServerError)
			return
		}
		writeSSE(w, messages[i])
	}))
	t.Cleanup(model.Close)

	policy, err := acl.Parse([]acl.Rule{{Name: "a", Groups: []string{"equipe-a-viewer"}, Indices: []string{"equipe-a-*"}, Actions: []string{"read"}}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse(es.URL)
	f.h = &Handler{
		Target: target, Policy: func() *acl.Policy { return policy },
		Resolver:  testResolver{all: []string{"equipe-a-sample", "equipe-b-sample"}},
		Enrich:    mapEnrich{"sp05-owners-a-policy": {"equipe-a-sp05-owners"}, "sp05-owners-b-policy": {"equipe-b-sp05-owners"}},
		RunAsUser: "svc", RunAsPassword: "pw",
		ModelURL: model.URL, ModelKey: "k", ModelName: "m",
	}
	return f
}

// writeSSE streams one model reply. A "deltas:" entry is a JSON array of
// content fragments; any other entry is one assistant message (tool_calls get an index).
func writeSSE(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/event-stream")
	send := func(delta any) {
		b, _ := json.Marshal(map[string]any{"choices": []map[string]any{{"delta": delta}}})
		fmt.Fprintf(w, "data: %s\n\n", b)
		w.(http.Flusher).Flush()
	}
	if parts, ok := strings.CutPrefix(msg, "deltas:"); ok {
		var ds []string
		json.Unmarshal([]byte(parts), &ds)
		for _, d := range ds {
			send(map[string]string{"content": d})
		}
	} else {
		var m map[string]any
		json.Unmarshal([]byte(msg), &m)
		if tcs, ok := m["tool_calls"].([]any); ok {
			for i, tc := range tcs {
				tc.(map[string]any)["index"] = i
			}
		}
		send(m)
	}
	fmt.Fprint(w, "data: [DONE]\n\n")
}

func deltas(parts ...string) string {
	b, _ := json.Marshal(parts)
	return "deltas:" + string(b)
}

func (f *fakes) valuesJSON() string {
	n := f.rowCount
	if n <= 1 {
		return `{"columns":[{"name":"host","type":"keyword"}],"values":[["h1"]]}`
	}
	rows := make([]string, n)
	for i := 0; i < n; i++ {
		rows[i] = fmt.Sprintf(`["r%d"]`, i)
	}
	return `{"columns":[{"name":"host","type":"keyword"}],"values":[` + strings.Join(rows, ",") + `]}`
}

func (f *fakes) post(body string) (int, response) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(body))
	f.h.Serve(w, r, auth.Identity{Subject: "alice", Groups: []string{"equipe-a-viewer"}})
	var out response
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func answer(text string) string {
	b, _ := json.Marshal(map[string]string{"role": "assistant", "content": text})
	return string(b)
}

func toolCallMsg(id, name string, args any) string {
	raw, _ := json.Marshal(args)
	msg := map[string]any{
		"role": "assistant",
		"tool_calls": []map[string]any{{
			"id":   id,
			"type": "function",
			"function": map[string]any{
				"name":      name,
				"arguments": string(raw),
			},
		}},
	}
	b, _ := json.Marshal(msg)
	return string(b)
}

func TestSchemaListsOnlyReadableIndices(t *testing.T) {
	f := newFakes(t, answer("none"))
	code, out := f.post(`{"question":"errors?"}`)
	if code != 200 || out.Error != "" || out.Answer != "none" {
		t.Fatalf("code %d out %+v", code, out)
	}
	for _, p := range f.paths {
		if strings.Contains(p, "equipe-b") {
			t.Fatalf("mapping asked for %q", p)
		}
	}
	if !strings.Contains(f.paths[0], "equipe-a-sample") {
		t.Fatalf("mapping asked for %q", f.paths)
	}
	if strings.Contains(f.modelBody[0], "equipe-b") || !strings.Contains(f.modelBody[0], "equipe-a-sample: host keyword") {
		t.Fatalf("model prompt leaks or misses schema: %s", f.modelBody[0])
	}
	if !strings.Contains(f.modelBody[0], "untrusted data") || !strings.Contains(f.modelBody[0], "run_esql") {
		t.Fatalf("prompt missing tools or untrusted-data line: %s", f.modelBody[0])
	}
}

func TestTwoQueriesThenAnswer(t *testing.T) {
	f := newFakes(t,
		toolCallMsg("1", "run_esql", map[string]string{"query": "FROM equipe-a-sample | STATS c = COUNT(*)"}),
		toolCallMsg("2", "run_esql", map[string]string{"query": "FROM equipe-a-sample | STATS c = COUNT(*) BY host"}),
		answer("142 errors, mostly h1"),
	)
	var buf bytes.Buffer
	f.h.Audit = audit.New(&buf, nil)
	_, out := f.post(`{"question":"how many errors, and from which hosts?"}`)
	if f.modelCalls.Load() != 3 || len(f.queries) != 2 || out.Error != "" {
		t.Fatalf("model %d queries %v out %+v", f.modelCalls.Load(), f.queries, out)
	}
	if out.Answer != "142 errors, mostly h1" || len(out.Steps) != 2 {
		t.Fatalf("got %+v", out)
	}
	if out.Steps[0].ESQL != f.queries[0] || !strings.Contains(string(out.Steps[1].Values), "h1") {
		t.Fatalf("steps %+v", out.Steps)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit lines: %s", buf.String())
	}
	for i, line := range lines {
		var rec audit.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if rec.User != "alice" || rec.Decision != audit.DecisionAllowed || rec.Query != f.queries[i] || rec.Rows != 1 {
			t.Fatalf("audit %+v", rec)
		}
		if strings.Contains(line, "h1") {
			t.Fatalf("audit must not contain row values: %s", line)
		}
	}
}

func TestForbiddenIndexDenied(t *testing.T) {
	f := newFakes(t,
		toolCallMsg("1", "run_esql", map[string]string{"query": "FROM equipe-b-sample"}),
		answer("142"),
	)
	var buf bytes.Buffer
	f.h.Audit = audit.New(&buf, nil)
	_, out := f.post(`{"question":"errors on b?"}`)
	if len(f.queries) != 0 || !strings.Contains(out.Error, "access denied") {
		t.Fatalf("got %+v queries %v", out, f.queries)
	}
	if !strings.Contains(f.modelBody[1], strings.TrimRight(untrustedPrefix, "\n")) || !strings.Contains(f.modelBody[1], "access denied") {
		t.Fatalf("tool result: %s", f.modelBody[1])
	}
	var rec audit.Record
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Decision != audit.DecisionDenied || rec.User != "alice" || !strings.Contains(rec.Query, "equipe-b-sample") {
		t.Fatalf("audit %+v", rec)
	}
}

func TestCrossTeamENRICHDeniedBeforeQuery(t *testing.T) {
	f := newFakes(t,
		toolCallMsg("1", "run_esql", map[string]string{"query": "FROM equipe-a-sample | ENRICH sp05-owners-b-policy ON host"}),
		answer("no"),
	)
	_, out := f.post(`{"question":"owners?"}`)
	if out.Error == "" || len(f.queries) != 0 {
		t.Fatalf("cross-team ENRICH must be denied before /_query, got %+v queries %v", out, f.queries)
	}
	if !strings.Contains(out.Error, "equipe-b-sp05-owners") {
		t.Fatalf("error should name the foreign source index: %q", out.Error)
	}
}

func TestSameTeamENRICHAllowed(t *testing.T) {
	f := newFakes(t,
		toolCallMsg("1", "run_esql", map[string]string{"query": "FROM equipe-a-sample | ENRICH sp05-owners-a-policy ON host"}),
		answer("ok"),
	)
	_, out := f.post(`{"question":"owners?"}`)
	if out.Error != "" || len(f.queries) != 1 || len(out.Steps) != 1 {
		t.Fatalf("got %+v queries %v", out, f.queries)
	}
}

func TestUncertainESQLDenied(t *testing.T) {
	f := newFakes(t,
		toolCallMsg("1", "run_esql", map[string]string{"query": "bad"}),
		answer("no"),
	)
	_, out := f.post(`{"question":"?"}`)
	if out.Error == "" || len(f.queries) != 0 {
		t.Fatalf("uncertain query must not reach ES: %+v queries %v", out, f.queries)
	}
}

func TestUnknownToolNotExecuted(t *testing.T) {
	f := newFakes(t,
		toolCallMsg("1", "drop_index", map[string]string{"query": "FROM equipe-a-sample"}),
		answer("no"),
	)
	_, out := f.post(`{"question":"drop it"}`)
	if len(f.queries) != 0 || out.Error != "" || out.Answer != "no" {
		t.Fatalf("got %+v queries %v", out, f.queries)
	}
	if !strings.Contains(f.modelBody[1], "unknown tool") {
		t.Fatalf("tool result: %s", f.modelBody[1])
	}
}

func TestToolResultTruncatedToMaxRows(t *testing.T) {
	f := newFakes(t,
		toolCallMsg("1", "run_esql", map[string]string{"query": "FROM equipe-a-sample"}),
		answer("many"),
	)
	f.rowCount = 60
	var buf bytes.Buffer
	f.h.Audit = audit.New(&buf, nil)
	_, out := f.post(`{"question":"all rows"}`)
	if out.Error != "" || len(out.Steps) != 1 {
		t.Fatalf("got %+v", out)
	}
	var shown []json.RawMessage
	if err := json.Unmarshal(out.Steps[0].Values, &shown); err != nil || len(shown) != maxRows {
		t.Fatalf("step rows %d err %v", len(shown), err)
	}
	if !strings.Contains(f.modelBody[1], strings.TrimRight(untrustedPrefix, "\n")) {
		t.Fatalf("tool message missing untrusted prefix: %s", f.modelBody[1])
	}
	var req struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(f.modelBody[1]), &req); err != nil {
		t.Fatal(err)
	}
	var toolRows int
	for _, m := range req.Messages {
		i := strings.Index(m.Content, "{")
		if i < 0 {
			continue
		}
		var payload struct {
			Values []json.RawMessage `json:"values"`
		}
		if json.Unmarshal([]byte(m.Content[i:]), &payload) == nil && len(payload.Values) > toolRows {
			toolRows = len(payload.Values)
		}
	}
	if toolRows != maxRows {
		t.Fatalf("model saw %d rows", toolRows)
	}
	var rec audit.Record
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Rows != 60 {
		t.Fatalf("audit should count rows before truncation, got %d", rec.Rows)
	}
}

func TestGetSchemaForbiddenIndex(t *testing.T) {
	f := newFakes(t,
		toolCallMsg("1", "get_schema", map[string]string{"index": "equipe-b-sample"}),
		answer("no"),
	)
	_, out := f.post(`{"question":"fields of b?"}`)
	if !strings.Contains(out.Error, "access denied") {
		t.Fatalf("got %+v", out)
	}
	for _, p := range f.paths {
		if strings.Contains(p, "equipe-b") {
			t.Fatalf("forbidden schema fetched %s", p)
		}
	}
}

func TestESErrorIsToolResult(t *testing.T) {
	f := newFakes(t,
		toolCallMsg("1", "run_esql", map[string]string{"query": "FROM equipe-a-sample | KEEP bad"}),
		toolCallMsg("2", "run_esql", map[string]string{"query": "FROM equipe-a-sample | KEEP host"}),
		answer("hosts"),
	)
	_, out := f.post(`{"question":"hosts?"}`)
	if f.modelCalls.Load() != 3 || len(f.queries) != 2 || out.Error != "" || out.Answer != "hosts" || len(out.Steps) != 1 {
		t.Fatalf("model %d queries %v out %+v", f.modelCalls.Load(), f.queries, out)
	}
	if !strings.Contains(f.modelBody[1], "Unknown column") {
		t.Fatalf("error not returned to the model: %s", f.modelBody[1])
	}
}

func TestTurnCap(t *testing.T) {
	msgs := make([]string, maxTurns)
	for i := range msgs {
		msgs[i] = toolCallMsg(fmt.Sprintf("c%d", i), "run_esql", map[string]string{"query": "FROM equipe-a-sample"})
	}
	f := newFakes(t, msgs...)
	_, out := f.post(`{"question":"loop"}`)
	if f.modelCalls.Load() != maxTurns || len(f.queries) != maxTurns || out.Answer != "" {
		t.Fatalf("model %d queries %d out %+v", f.modelCalls.Load(), len(f.queries), out)
	}
	if !strings.Contains(out.Error, "stopped after 6 turns") || len(out.Steps) != maxTurns {
		t.Fatalf("got %+v", out)
	}
}

func TestQuestionRequired(t *testing.T) {
	f := newFakes(t)
	code, out := f.post(`{"esql":"FROM equipe-a-sample | LIMIT 1"}`)
	if code != 400 || out.Error == "" || f.modelCalls.Load() != 0 || len(f.queries) != 0 {
		t.Fatalf("code %d model %d queries %v out %+v", code, f.modelCalls.Load(), f.queries, out)
	}
}

func TestNoModelIs503(t *testing.T) {
	var h *Handler
	w := httptest.NewRecorder()
	h.Serve(w, httptest.NewRequest(http.MethodPost, Path, strings.NewReader(`{}`)), auth.Identity{})
	if w.Code != 503 || w.Header().Get("X-elastic-product") != "Elasticsearch" {
		t.Fatalf("code %d", w.Code)
	}
}

func TestAfterRunNeverWidens(t *testing.T) {
	cols := json.RawMessage(`[{"name":"host"}]`)
	var rows []json.RawMessage
	for i := 0; i < maxRows+10; i++ {
		rows = append(rows, json.RawMessage(fmt.Sprintf(`["r%d"]`, i)))
	}
	raw, _ := json.Marshal(rows)
	gotCols, gotVals := afterRun(cols, raw)
	if string(gotCols) != string(cols) {
		t.Fatalf("columns changed: %s", gotCols)
	}
	var out []json.RawMessage
	if err := json.Unmarshal(gotVals, &out); err != nil || len(out) != maxRows {
		t.Fatalf("len %d err %v", len(out), err)
	}
	if len(out) > len(rows) {
		t.Fatal("afterRun added rows")
	}
}

// sseEvent is one parsed "event:/data:" pair.
type sseEvent struct{ Name, Data string }

func parseSSE(body string) []sseEvent {
	var evs []sseEvent
	for _, blk := range strings.Split(strings.TrimSpace(body), "\n\n") {
		var e sseEvent
		for _, line := range strings.Split(blk, "\n") {
			if v, ok := strings.CutPrefix(line, "event: "); ok {
				e.Name = v
			} else if v, ok := strings.CutPrefix(line, "data: "); ok {
				e.Data = v
			}
		}
		evs = append(evs, e)
	}
	return evs
}

// flushRecorder records the body length at each Flush.
type flushRecorder struct {
	*httptest.ResponseRecorder
	flushedAt []int
}

func (f *flushRecorder) Flush() {
	f.flushedAt = append(f.flushedAt, f.Body.Len())
	f.ResponseRecorder.Flush()
}

func (f *fakes) postSSE(body string) *flushRecorder {
	w := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(body))
	r.Header.Set("Accept", "text/event-stream")
	f.h.Serve(w, r, auth.Identity{Subject: "alice", Groups: []string{"equipe-a-viewer"}})
	return w
}

func TestSSETokensThenDone(t *testing.T) {
	f := newFakes(t, deltas("Hel", "lo"))
	w := f.postSSE(`{"question":"hi"}`)
	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type %q", ct)
	}
	evs := parseSSE(w.Body.String())
	if len(evs) != 3 || evs[0].Name != "token" || evs[1].Name != "token" || evs[2].Name != "done" {
		t.Fatalf("events %+v", evs)
	}
	if evs[0].Data != `{"text":"Hel"}` || evs[1].Data != `{"text":"lo"}` || !strings.Contains(evs[2].Data, `"answer":"Hello"`) {
		t.Fatalf("events %+v", evs)
	}
	// every event is flushed on its own, so the first token leaves before the handler ends.
	first := len("event: token\ndata: {\"text\":\"Hel\"}\n\n")
	found := false
	for _, n := range w.flushedAt {
		if n == first {
			found = true
		}
	}
	if !found || len(w.flushedAt) < 4 {
		t.Fatalf("flushes %v, want one right after the first token (%d)", w.flushedAt, first)
	}
}

func TestSSEStepEvent(t *testing.T) {
	f := newFakes(t,
		toolCallMsg("1", "run_esql", map[string]string{"query": "FROM equipe-a-sample | LIMIT 1"}),
		toolCallMsg("2", "get_schema", map[string]string{"index": "equipe-a-sample"}),
		answer("ok"),
	)
	evs := parseSSE(f.postSSE(`{"question":"q"}`).Body.String())
	var steps []string
	for _, e := range evs {
		if e.Name == "step" {
			steps = append(steps, e.Data)
		}
	}
	if len(steps) != 2 || !strings.Contains(steps[0], `"esql"`) || steps[1] != `{"index":"equipe-a-sample"}` {
		t.Fatalf("steps %v", steps)
	}
}

func TestCancelAfterFirstToolStopsLoop(t *testing.T) {
	f := newFakes(t,
		toolCallMsg("1", "run_esql", map[string]string{"query": "FROM equipe-a-sample"}),
		answer("never"),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// ES answers /_query, then the client goes away (Stop).
	inner := f.h.Target
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_query" {
			cancel()
			w.Write([]byte(`{"columns":[],"values":[]}`))
			return
		}
		http.Redirect(w, r, inner.String()+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer es.Close()
	f.h.Target, _ = url.Parse(es.URL)
	// GET /_mapping is redirected back to the original ES.
	w := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(`{"question":"q"}`)).WithContext(ctx)
	r.Header.Set("Accept", "text/event-stream")
	f.h.Serve(w, r, auth.Identity{Subject: "alice", Groups: []string{"equipe-a-viewer"}})
	if f.modelCalls.Load() != 1 {
		t.Fatalf("model called %d times after Stop", f.modelCalls.Load())
	}
	if strings.Contains(w.Body.String(), "event: done") || strings.Contains(w.Body.String(), "never") {
		t.Fatalf("wrote after Stop: %s", w.Body.String())
	}
}

func TestHistoryBeforeQuestion(t *testing.T) {
	f := newFakes(t, answer("ok"))
	code, out := f.post(`{"question":"and now?","history":[{"role":"user","content":"first q"},{"role":"assistant","content":"first a"}]}`)
	if code != 200 || out.Error != "" {
		t.Fatalf("code %d out %+v", code, out)
	}
	b := f.modelBody[0]
	i, j, k := strings.Index(b, "first q"), strings.Index(b, "first a"), strings.Index(b, "Question: and now?")
	if i < 0 || !(i < j && j < k) || strings.Index(b, "Schema (index") > i {
		t.Fatalf("order wrong in %s", b)
	}
}

func TestHistoryRejected(t *testing.T) {
	f := newFakes(t)
	many := strings.Repeat(`{"role":"user","content":"x"},`, maxHistory) + `{"role":"user","content":"x"}`
	big := strings.Repeat("a", maxHistoryBytes+1)
	for name, body := range map[string]string{
		"role":  `{"question":"q","history":[{"role":"tool","content":"x"}]}`,
		"count": `{"question":"q","history":[` + many + `]}`,
		"size":  `{"question":"q","history":[{"role":"user","content":"` + big + `"}]}`,
	} {
		if code, out := f.post(body); code != 400 || out.Error == "" {
			t.Fatalf("%s: code %d out %+v", name, code, out)
		}
	}
	if f.modelCalls.Load() != 0 {
		t.Fatal("model must not be called")
	}
}
