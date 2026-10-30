package fuzz

import (
	"encoding/json"
	"testing"

	"github.com/YarKhan02/PathWise/internal/model"
)

// TestFieldsFromFact decodes through a JSON round-trip, the way the engine reads
// a request_schema fact back from storage — the attrs come back as []any of
// map[string]any, not the in-memory []map[string]any.
func TestFieldsFromFact(t *testing.T) {
	attrs := map[string]any{
		"fields": []map[string]any{
			{"name": "email", "in": "body", "goType": "string", "required": true},
			{"name": "id", "in": "path", "goType": "string", "required": false},
			{"name": "", "in": "body"}, // malformed: no name, must be skipped
		},
	}
	raw, err := json.Marshal(attrs)
	if err != nil {
		t.Fatal(err)
	}
	var roundTripped map[string]any
	if err := json.Unmarshal(raw, &roundTripped); err != nil {
		t.Fatal(err)
	}

	got := FieldsFromFact(model.Fact{Attrs: roundTripped})
	if len(got) != 2 {
		t.Fatalf("got %d fields, want 2 (malformed entry skipped): %+v", len(got), got)
	}
	if got[0] != (Field{Name: "email", In: "body", GoType: "string", Required: true}) {
		t.Errorf("field[0] = %+v", got[0])
	}
	if got[1].Required {
		t.Errorf("field[1] required should be false after round-trip, got %+v", got[1])
	}
}

// TestFieldsFromFactMissing is the negative control: a fact with no fields attr
// yields no fields and does not panic.
func TestFieldsFromFactMissing(t *testing.T) {
	if got := FieldsFromFact(model.Fact{}); len(got) != 0 {
		t.Errorf("empty fact should yield no fields, got %+v", got)
	}
}
