package fuzz

import "github.com/YarKhan02/PathWise/internal/model"

// FieldsFromFact decodes a request_schema fact into typed Fields. The fact is
// read from storage, where JSON unmarshalling has turned its attrs into generic
// maps ([]any of map[string]any), so the decoder accepts that shape as well as
// the in-memory one. Malformed entries are skipped, not fatal: a schema fact is
// untrusted input to the fuzzer, not a guaranteed-well-formed struct.
func FieldsFromFact(f model.Fact) []Field {
	items := fieldItems(f.Attrs["fields"])
	out := make([]Field, 0, len(items))
	for _, m := range items {
		name, _ := m["name"].(string)
		if name == "" {
			continue
		}
		in, _ := m["in"].(string)
		gt, _ := m["goType"].(string)
		req, _ := m["required"].(bool)
		out = append(out, Field{Name: name, In: in, GoType: gt, Required: req})
	}
	return out
}

// fieldItems coerces the "fields" attr to a slice of maps, handling both the
// in-memory ([]map[string]any) and storage-round-tripped ([]any) forms.
func fieldItems(v any) []map[string]any {
	switch t := v.(type) {
	case []map[string]any:
		return t
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, e := range t {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}
