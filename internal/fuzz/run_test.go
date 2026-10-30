package fuzz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// buggyApp is a target with one planted defect: POST /assignments accepts a body
// even when the required "title" is missing (it should 400), stores it, and then
// GET /assignments/{id} 500s because it cannot render a row with no title. That
// is exactly the "write accepts bad input, read fails" inconsistency.
func buggyApp() http.Handler {
	store := map[string]map[string]any{}
	next := 0
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/assignments":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			next++
			id := strconv.Itoa(next)
			store[id] = body // BUG: stored without validating required fields
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": next})

		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/assignments/"):
			id := strings.TrimPrefix(r.URL.Path, "/assignments/")
			row, ok := store[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if _, hasTitle := row["title"]; !hasTitle || row["title"] == nil {
				w.WriteHeader(http.StatusInternalServerError) // BUG: can't render incomplete row
				return
			}
			row["id"] = id
			_ = json.NewEncoder(w).Encode(row)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestRunDetectsWriteReadInconsistency(t *testing.T) {
	srv := httptest.NewServer(buggyApp())
	defer srv.Close()

	eps := []Endpoint{
		{Method: "POST", Path: "/assignments", Fields: []Field{
			{Name: "title", In: "body", GoType: "string", Required: true},
		}},
		{Method: "GET", Path: "/assignments/{id}", Fields: []Field{
			{Name: "id", In: "path", GoType: "string"},
		}},
	}

	breaks := Run(context.Background(), NewClient(srv.URL), RunConfig{Endpoints: eps})

	// The missing:title and null:title payloads are accepted then fail on read.
	gotLabels := map[string]BreakKind{}
	for _, b := range breaks {
		if b.Endpoint != "POST /assignments" {
			t.Errorf("unexpected break endpoint %q", b.Endpoint)
		}
		gotLabels[b.Payload] = b.Kind
	}
	if gotLabels["missing:title"] != BreakWriteReadInconsistency {
		t.Errorf("missing:title: got %q, want write_read_inconsistency (breaks=%+v)", gotLabels["missing:title"], breaks)
	}
	if gotLabels["null:title"] != BreakWriteReadInconsistency {
		t.Errorf("null:title: got %q, want write_read_inconsistency", gotLabels["null:title"])
	}

	// Negative control: the valid baseline round-trips cleanly and the app's
	// correct 404/200 paths produce no finding.
	if _, flagged := gotLabels["baseline"]; flagged {
		t.Errorf("baseline (valid) must not be flagged: %+v", breaks)
	}
}

// TestRunCleanAppFindsNothing is the false-positive guard: an app that validates
// correctly yields no breaks.
func TestRunCleanAppFindsNothing(t *testing.T) {
	store := map[string]map[string]any{}
	next := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/assignments":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if t, ok := body["title"].(string); !ok || t == "" {
				w.WriteHeader(http.StatusBadRequest) // correctly rejects bad input
				return
			}
			next++
			id := strconv.Itoa(next)
			store[id] = body
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": next})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/assignments/"):
			row, ok := store[strings.TrimPrefix(r.URL.Path, "/assignments/")]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(row)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	eps := []Endpoint{
		{Method: "POST", Path: "/assignments", Fields: []Field{{Name: "title", In: "body", GoType: "string", Required: true}}},
		{Method: "GET", Path: "/assignments/{id}", Fields: []Field{{Name: "id", In: "path", GoType: "string"}}},
	}
	if breaks := Run(context.Background(), NewClient(srv.URL), RunConfig{Endpoints: eps}); len(breaks) != 0 {
		t.Errorf("clean app should yield no breaks, got %+v", breaks)
	}
}
