package fuzz

import (
	"context"
	"strings"
	"testing"
)

// stubMutator returns fixed values for body string fields, standing in for a
// real model so the mutation layer is testable without Ollama.
type stubMutator struct{ vals []any }

func (s stubMutator) Values(_ context.Context, f Field) []any {
	if f.In != "body" {
		return nil
	}
	return s.vals
}

func TestPayloadsWith(t *testing.T) {
	fields := []Field{
		{Name: "title", In: "body", GoType: "string", Required: true},
		{Name: "id", In: "path", GoType: "string"},
	}

	// A nil mutator yields exactly the deterministic set.
	if got := PayloadsWith(context.Background(), fields, nil); len(got) != len(Payloads(fields)) {
		t.Errorf("nil mutator should equal Payloads, got %d vs %d", len(got), len(Payloads(fields)))
	}

	got := PayloadsWith(context.Background(), fields, stubMutator{vals: []any{"' OR 1=1", "<script>"}})
	labels := byLabel(got)

	// The deterministic payloads are still present...
	if _, ok := labels["baseline"]; !ok {
		t.Errorf("deterministic baseline missing after mutation")
	}
	if _, ok := labels["missing:title"]; !ok {
		t.Errorf("deterministic missing:title dropped")
	}
	// ...plus one llm payload per value, on the body field only.
	if p, ok := labels["llm:title#0"]; !ok || p.Body["title"] != "' OR 1=1" {
		t.Errorf("llm:title#0 missing or wrong: %+v", p)
	}
	if _, ok := labels["llm:title#1"]; !ok {
		t.Errorf("llm:title#1 missing")
	}
	// The path field is never given a body mutation.
	for l := range labels {
		if strings.HasPrefix(l, "llm:id") {
			t.Errorf("path field must not get an llm body payload: %s", l)
		}
	}
}

func TestParseOllamaValues(t *testing.T) {
	// Prose around a JSON array is tolerated; non-strings are dropped; capped at n.
	in := "Sure! Here are values:\n[\"' OR 1=1\", \"<script>\", 42, \"\\u0000\", \"a\", \"b\"]\nHope that helps."
	got := parseOllamaValues(in, 3)
	if len(got) != 3 {
		t.Fatalf("want 3 values (capped), got %d: %v", len(got), got)
	}
	if got[0] != "' OR 1=1" || got[1] != "<script>" {
		t.Errorf("parsed values wrong: %v", got)
	}

	// Negative control: no array, or malformed JSON, yields nil — never a panic.
	if v := parseOllamaValues("no array here", 6); v != nil {
		t.Errorf("want nil for prose with no array, got %v", v)
	}
	if v := parseOllamaValues("[not, valid, json]", 6); v != nil {
		t.Errorf("want nil for malformed array, got %v", v)
	}
}
