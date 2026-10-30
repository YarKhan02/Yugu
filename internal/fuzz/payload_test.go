package fuzz

import "testing"

// byLabel indexes payloads by their label for assertion.
func byLabel(ps []Payload) map[string]Payload {
	m := map[string]Payload{}
	for _, p := range ps {
		m[p.Label] = p
	}
	return m
}

func TestPayloads(t *testing.T) {
	fields := []Field{
		{Name: "email", In: "body", GoType: "string", Required: true},
		{Name: "age", In: "body", GoType: "int", Required: true},
		{Name: "nickname", In: "body", GoType: "string"}, // optional
		{Name: "id", In: "path", GoType: "string"},       // not a body field
	}
	got := byLabel(Payloads(fields))

	// Baseline sets every body field to a type-correct value and ignores params.
	base, ok := got["baseline"]
	if !ok || !base.Valid {
		t.Fatalf("baseline missing or not valid: %+v", base)
	}
	if _, ok := base.Body["id"]; ok {
		t.Errorf("baseline body must not include path param id: %v", base.Body)
	}
	if s, ok := base.Body["email"].(string); !ok || s == "" {
		t.Errorf("baseline email should be a non-empty string, got %v", base.Body["email"])
	}
	if _, ok := base.Body["age"].(int); !ok {
		t.Errorf("baseline age should be an int, got %T", base.Body["age"])
	}

	// A required field gets missing: and null: mutations; an optional one does not.
	if _, ok := got["missing:email"]; !ok {
		t.Errorf("expected missing:email mutation")
	}
	if _, ok := got["null:age"]; !ok {
		t.Errorf("expected null:age mutation")
	}
	if _, ok := got["missing:nickname"]; ok {
		t.Errorf("optional nickname must not get a missing: mutation")
	}

	// missing:email omits the key entirely but keeps the rest.
	if m := got["missing:email"]; m.Valid {
		t.Errorf("missing:email should be invalid")
	} else if _, present := m.Body["email"]; present {
		t.Errorf("missing:email must omit the email key: %v", m.Body)
	} else if _, present := m.Body["age"]; !present {
		t.Errorf("missing:email must keep other fields: %v", m.Body)
	}

	// wrongType:age violates the number type with a string.
	if w, ok := got["wrongType:age"]; !ok {
		t.Errorf("expected wrongType:age mutation")
	} else if _, isStr := w.Body["age"].(string); !isStr {
		t.Errorf("wrongType:age should set age to a string, got %T", w.Body["age"])
	}
}

// TestPayloadsUnknownType is the negative control: a type the fuzzer does not
// understand gets a baseline value but no type-violation mutation, because it
// cannot name a value that violates an unknown type.
func TestPayloadsUnknownType(t *testing.T) {
	got := byLabel(Payloads([]Field{{Name: "meta", In: "body", GoType: "map[string]interface {}", Required: false}}))
	if _, ok := got["baseline"]; !ok {
		t.Errorf("expected a baseline even for an unknown-typed field")
	}
	if _, ok := got["wrongType:meta"]; ok {
		t.Errorf("unknown type must not get a wrongType mutation")
	}
}
