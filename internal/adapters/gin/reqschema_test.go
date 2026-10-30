package gin_test

import (
	"testing"

	"golang.org/x/tools/go/ssa"

	ginadapter "github.com/YarKhan02/PathWise/internal/adapters/gin"
	"github.com/YarKhan02/PathWise/internal/analyzer"
	"github.com/YarKhan02/PathWise/internal/loader"
	"github.com/YarKhan02/PathWise/internal/model"
)

// TestRequestSchema is the exit criterion for request-shape extraction: the
// inputs a handler reads from the request (body fields, path and query
// parameters) must be recovered from its SSA, so the fuzzer has a valid shape to
// mutate. basic-gin is the ground truth — Login binds a JSON body, GetStudent
// reads a path id, SearchStudents reads two query keys.
func TestRequestSchema(t *testing.T) {
	loaded, err := loader.Load(corpusApp(t))
	if err != nil {
		t.Fatalf("load corpus app: %v", err)
	}
	if errs := loaded.BuildErrors(); len(errs) > 0 {
		t.Fatalf("corpus app did not type-check: %v", errs)
	}
	funcs := analyzer.FunctionsByName(loaded.Prog)

	type field struct{ in, name string }
	cases := map[string][]field{
		"main.Login":            {{"body", "email"}, {"body", "password"}},
		"main.GetStudent":       {{"path", "id"}},
		"main.SearchStudents":   {{"query", "q"}},
		"main.TeacherDashboard": {{"query", "strict"}},
		// A handler that reads nothing must yield an empty schema, not a guess —
		// the negative control against inventing inputs.
		"main.ListBatches": nil,
	}

	for name, want := range cases {
		fn := funcs[name]
		if fn == nil {
			t.Errorf("%s: handler not found in program", name)
			continue
		}
		got := map[field]ginadapter.RequestField{}
		for _, f := range ginadapter.HandlerSchema(fn).Fields {
			got[field{f.In, f.Name}] = f
		}
		if len(got) != len(want) {
			t.Errorf("%s: got %d fields %v, want %d", name, len(got), got, len(want))
		}
		for _, w := range want {
			f, ok := got[w]
			if !ok {
				t.Errorf("%s: missing %s field %q", name, w.in, w.name)
				continue
			}
			if w.in == "body" && f.GoType != "string" {
				t.Errorf("%s: body %q GoType = %q, want string", name, w.name, f.GoType)
			}
		}
	}
}

// fieldKeys reduces a request_schema fact's "fields" attr to an "in/name" set.
func fieldKeys(f model.Fact) map[string]bool {
	out := map[string]bool{}
	for _, raw := range f.Attrs["fields"].([]map[string]any) {
		out[raw["in"].(string)+"/"+raw["name"].(string)] = true
	}
	return out
}

func TestSchemaFacts(t *testing.T) {
	loaded, err := loader.Load(corpusApp(t))
	if err != nil {
		t.Fatalf("load corpus app: %v", err)
	}
	res := ginadapter.Discover(loaded.Prog, loaded.Packages)
	funcs := analyzer.FunctionsByName(loaded.Prog)

	bySubject := map[string]model.Fact{}
	for _, f := range ginadapter.SchemaFacts("scan1", res.Routes, funcs) {
		if f.Kind != model.FactRequestSchema {
			t.Fatalf("unexpected fact kind %q", f.Kind)
		}
		bySubject[f.Subject] = f
	}

	if keys := fieldKeys(bySubject["POST /login"]); !keys["body/email"] || !keys["body/password"] {
		t.Errorf("POST /login fields = %v, want body/email and body/password", keys)
	}
	if keys := fieldKeys(bySubject["GET /students/{id}"]); !keys["path/id"] {
		t.Errorf("GET /students/{id} fields = %v, want path/id", keys)
	}

	// An unresolved handler must still contribute its pattern path parameter and
	// be recorded as unknown — a gap in body coverage, never silently empty.
	synth := ginadapter.SchemaFacts("scan1",
		[]ginadapter.Route{{Method: "GET", Pattern: "/widgets/{wid}", Handler: "main.Unresolved"}},
		map[string]*ssa.Function{})
	if len(synth) != 1 {
		t.Fatalf("synthetic route: got %d facts, want 1", len(synth))
	}
	if keys := fieldKeys(synth[0]); !keys["path/wid"] {
		t.Errorf("unresolved handler: fields = %v, want path/wid from pattern", keys)
	}
	if unk, _ := synth[0].Attrs["unknown"].([]string); len(unk) == 0 {
		t.Errorf("unresolved handler: want an unknown reason, got none")
	}
}
