package ask

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"proxy/internal/acl"
	"proxy/internal/auth"
)

type fixedResolver []string

func (f fixedResolver) Resolve(context.Context, []string) ([]string, error) { return f, nil }

type fakes struct {
	h          *Handler
	modelCalls atomic.Int32
	queries    []string
	mappingURL string
	modelBody  []string
}

// newFakes: model replies come from replies in order; /_query fails for
// every query containing "bad".
func newFakes(t *testing.T, replies ...string) *fakes {
	t.Helper()
	f := &fakes{}
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		switch {
		case strings.HasSuffix(r.URL.Path, "/_mapping"):
			f.mappingURL = r.URL.Path
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
			w.Write([]byte(`{"columns":[{"name":"host","type":"keyword"}],"values":[["h1"]]}`))
		default:
			t.Errorf("unexpected ES path %s", r.URL.Path)
		}
	}))
	t.Cleanup(es.Close)
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.modelBody = append(f.modelBody, string(b))
		i := int(f.modelCalls.Add(1)) - 1
		content, _ := json.Marshal(replies[i])
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":` + string(content) + `}}]}`))
	}))
	t.Cleanup(model.Close)

	policy, err := acl.Parse([]acl.Rule{{Name: "a", Groups: []string{"equipe-a-viewer"}, Indices: []string{"equipe-a-*"}, Actions: []string{"read"}}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse(es.URL)
	f.h = &Handler{
		Target: target, Policy: func() *acl.Policy { return policy },
		Resolver:  fixedResolver{"equipe-a-sample", "equipe-b-sample"},
		RunAsUser: "svc", RunAsPassword: "pw",
		ModelURL: model.URL, ModelKey: "k", ModelName: "m",
	}
	return f
}

func (f *fakes) post(body string) (int, response) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(body))
	f.h.Serve(w, r, auth.Identity{Subject: "alice", Groups: []string{"equipe-a-viewer"}})
	var out response
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestSchemaListsOnlyReadableIndices(t *testing.T) {
	f := newFakes(t, `{"esql":"FROM equipe-a-sample","explanation":"e"}`)
	code, out := f.post(`{"question":"errors?"}`)
	if code != 200 || out.Error != "" {
		t.Fatalf("code %d err %q", code, out.Error)
	}
	if strings.Contains(f.mappingURL, "equipe-b") || !strings.Contains(f.mappingURL, "equipe-a-sample") {
		t.Fatalf("mapping asked for %q", f.mappingURL)
	}
	if strings.Contains(f.modelBody[0], "equipe-b") || !strings.Contains(f.modelBody[0], "equipe-a-sample: host keyword") {
		t.Fatalf("model prompt leaks or misses schema: %s", f.modelBody[0])
	}
}

func TestFailedQueryRetriedOnce(t *testing.T) {
	f := newFakes(t,
		`{"esql":"FROM equipe-a-sample | KEEP bad","explanation":"first"}`,
		"```json\n"+`{"esql":"FROM equipe-a-sample | KEEP host","explanation":"fixed"}`+"\n```")
	_, out := f.post(`{"question":"hosts?"}`)
	if f.modelCalls.Load() != 2 || len(f.queries) != 2 {
		t.Fatalf("model %d, queries %v", f.modelCalls.Load(), f.queries)
	}
	if out.Error != "" || out.Explanation != "fixed" || !strings.Contains(string(out.Values), "h1") {
		t.Fatalf("got %+v", out)
	}
}

func TestSecondFailureReturnsQueryAndError(t *testing.T) {
	f := newFakes(t,
		`{"esql":"bad 1","explanation":"a"}`,
		`{"esql":"bad 2","explanation":"b"}`)
	_, out := f.post(`{"question":"x"}`)
	if f.modelCalls.Load() != 2 || len(f.queries) != 2 {
		t.Fatalf("expected exactly one retry, model %d queries %v", f.modelCalls.Load(), f.queries)
	}
	if out.ESQL != "bad 2" || !strings.Contains(out.Error, "Unknown column") {
		t.Fatalf("got %+v", out)
	}
}

func TestEditedQueryNeverCallsModel(t *testing.T) {
	f := newFakes(t)
	_, out := f.post(`{"esql":"FROM equipe-a-sample | LIMIT 1"}`)
	if f.modelCalls.Load() != 0 || len(f.queries) != 1 || out.Error != "" {
		t.Fatalf("model %d queries %v out %+v", f.modelCalls.Load(), f.queries, out)
	}
	// A failing edit is not retried either.
	_, out = f.post(`{"esql":"bad"}`)
	if f.modelCalls.Load() != 0 || out.Error == "" {
		t.Fatalf("model %d out %+v", f.modelCalls.Load(), out)
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
