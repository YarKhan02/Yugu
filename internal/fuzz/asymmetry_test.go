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

// asymmetricApp validates "name" on create but not on update — the planted
// inconsistency. POST /widgets rejects a missing name (400); PATCH
// /widgets/{id} accepts anything (200).
func asymmetricApp() http.Handler {
	next := 0
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/widgets":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if name, ok := body["name"].(string); !ok || name == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			next++
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": next})
		case (r.Method == "PATCH" || r.Method == "PUT") && strings.HasPrefix(r.URL.Path, "/widgets/"):
			w.WriteHeader(http.StatusOK) // BUG: no validation on update
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestRunDetectsValidationAsymmetry(t *testing.T) {
	srv := httptest.NewServer(asymmetricApp())
	defer srv.Close()

	eps := []Endpoint{
		{Method: "POST", Path: "/widgets", Fields: []Field{{Name: "name", In: "body", GoType: "string", Required: true}}},
		{Method: "PATCH", Path: "/widgets/{id}", Fields: []Field{
			{Name: "name", In: "body", GoType: "string", Required: true},
			{Name: "id", In: "path", GoType: "string"},
		}},
	}

	breaks := Run(context.Background(), NewClient(srv.URL), RunConfig{Endpoints: eps})

	var asym []Break
	for _, b := range breaks {
		if b.Kind == BreakValidationAsymmetry {
			asym = append(asym, b)
		}
	}
	if len(asym) != 1 {
		t.Fatalf("want exactly 1 validation_asymmetry break, got %d (all breaks: %+v)", len(asym), breaks)
	}
	if asym[0].Payload != "missing:name" {
		t.Errorf("asymmetry payload = %q, want missing:name", asym[0].Payload)
	}
	if !strings.Contains(asym[0].Endpoint, "POST /widgets") || !strings.Contains(asym[0].Endpoint, "PATCH /widgets/{id}") {
		t.Errorf("asymmetry endpoint = %q, want both create and update named", asym[0].Endpoint)
	}
}

// TestNoAsymmetryWhenConsistent is the negative control: when both endpoints
// validate the field the same way, no asymmetry is reported.
func TestNoAsymmetryWhenConsistent(t *testing.T) {
	next := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Both create and update reject a missing name — consistent, no break.
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		missing := func() bool { n, ok := body["name"].(string); return !ok || n == "" }
		switch {
		case r.Method == "POST" && r.URL.Path == "/widgets":
			if missing() {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			next++
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": strconv.Itoa(next)})
		case (r.Method == "PATCH") && strings.HasPrefix(r.URL.Path, "/widgets/"):
			if missing() {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	eps := []Endpoint{
		{Method: "POST", Path: "/widgets", Fields: []Field{{Name: "name", In: "body", GoType: "string", Required: true}}},
		{Method: "PATCH", Path: "/widgets/{id}", Fields: []Field{
			{Name: "name", In: "body", GoType: "string", Required: true},
			{Name: "id", In: "path", GoType: "string"},
		}},
	}
	for _, b := range Run(context.Background(), NewClient(srv.URL), RunConfig{Endpoints: eps}) {
		if b.Kind == BreakValidationAsymmetry {
			t.Errorf("consistent validation must not report asymmetry: %+v", b)
		}
	}
}
