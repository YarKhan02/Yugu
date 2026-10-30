// Package fuzz builds request payloads from an endpoint's statically-recovered
// request schema and classifies how the running application responds to them.
// It consumes the schema the analyzer emits (model.FactRequestSchema) and never
// parses source itself.
//
// Payload generation is deterministic by design: the same schema yields the
// same payloads every run, so a reported break is reproducible and a diff
// between two scans is meaningful. Non-deterministic value mutation (a local
// model proposing adversarial strings) is a later, additive layer over this
// base set, never a replacement for it.
package fuzz

import (
	"context"
	"fmt"
	"strings"
)

// Mutator supplies additional adversarial values for a body field — typically a
// local model proposing injection, overflow and unicode strings. It is optional:
// a nil Mutator means deterministic payloads only. Its values never replace the
// deterministic base set; they are layered on top.
type Mutator interface {
	Values(ctx context.Context, f Field) []any
}

// PayloadsWith returns the deterministic payloads plus, for each body field, one
// payload per value a Mutator proposes. The mutated values are type-valid
// adversarial inputs (a SQL-injection string is still a string), so they are
// marked Valid: they catch crashes and silent corruption, not schema-violation
// breaks, which the deterministic set already covers.
func PayloadsWith(ctx context.Context, fields []Field, m Mutator) []Payload {
	out := Payloads(fields)
	if m == nil {
		return out
	}
	baseline := out[0].Body // Payloads always returns the baseline first
	for _, f := range fields {
		if f.In != "body" {
			continue
		}
		for i, v := range m.Values(ctx, f) {
			out = append(out, Payload{
				Body:  with(baseline, f.Name, v),
				Label: fmt.Sprintf("llm:%s#%d", f.Name, i),
				Valid: true,
			})
		}
	}
	return out
}

// Field is one request input the fuzzer can set: a body field, or a path/query
// parameter. It mirrors the analyzer's request-schema fact, decoded from
// storage, so the fuzz engine does not depend on any framework adapter.
type Field struct {
	Name     string
	In       string // "body", "query", or "path"
	GoType   string // the Go type the handler binds, e.g. "string", "int"
	Required bool   // a body field the schema marks required
}

// Payload is one generated request body together with how it was derived and
// whether it satisfies the schema's stated constraints. Valid is the fuzzer's
// own expectation, not a verdict: the break is the gap between this expectation
// and what the app actually did (a Valid=false body the app accepts, then fails
// to read back).
type Payload struct {
	Body  map[string]any
	Label string // "baseline", "missing:<field>", "wrongType:<field>", "null:<field>"
	Valid bool
}

// kind is the coarse JSON-level category a Go type maps to. It is what decides a
// valid value and a type-violating one; the exact Go width (int32 vs int64) does
// not matter to a JSON body.
type kind int

const (
	kindString kind = iota
	kindNumber
	kindBool
	kindUnknown
)

// kindOf maps a Go type name to its JSON category. A pointer or slice element is
// categorized by its base; an unrecognized type is kindUnknown, which is given a
// string value and never used to assert a type violation (we cannot know what
// would violate a type we do not understand — preserve uncertainty).
func kindOf(goType string) kind {
	t := strings.TrimPrefix(strings.TrimSpace(goType), "*")
	switch t {
	case "string":
		return kindString
	case "bool":
		return kindBool
	case "int", "int8", "int16", "int32", "int64",
		"uint", "uint8", "uint16", "uint32", "uint64",
		"float32", "float64":
		return kindNumber
	default:
		return kindUnknown
	}
}

// validValue returns a schema-satisfying value for a kind. Values are fixed so
// payloads are reproducible.
func validValue(k kind) any {
	switch k {
	case kindNumber:
		return 1
	case kindBool:
		return true
	default: // string and unknown both take a plain string
		return "fuzz"
	}
}

// wrongValue returns a value whose JSON type violates the kind: a string where a
// number or bool is wanted, and a number where a string is wanted.
func wrongValue(k kind) any {
	switch k {
	case kindString:
		return 123
	default: // number and bool are both violated by a non-numeric string
		return "not-a-valid-value"
	}
}

// Payloads builds the deterministic payload set for a schema's body fields: a
// baseline valid body, then one mutation per field that isolates a single
// violation so a break can be attributed to exactly one input.
//
// Path and query parameters are not part of the body; the engine fills those
// into the URL separately (a later slice reuses validValue for them).
func Payloads(fields []Field) []Payload {
	var body []Field
	for _, f := range fields {
		if f.In == "body" {
			body = append(body, f)
		}
	}

	baseline := map[string]any{}
	for _, f := range body {
		baseline[f.Name] = validValue(kindOf(f.GoType))
	}
	out := []Payload{{Body: baseline, Label: "baseline", Valid: true}}

	for _, f := range body {
		k := kindOf(f.GoType)

		// A required field omitted: the "accepted a body missing a required
		// field" case. Only meaningful for required fields.
		if f.Required {
			out = append(out,
				Payload{Body: omit(baseline, f.Name), Label: "missing:" + f.Name, Valid: false},
				Payload{Body: with(baseline, f.Name, nil), Label: "null:" + f.Name, Valid: false},
			)
		}

		// A wrong-typed value, for every field whose type we understand. An
		// unknown type is skipped: we cannot name a value that violates it.
		if k != kindUnknown {
			out = append(out, Payload{Body: with(baseline, f.Name, wrongValue(k)), Label: "wrongType:" + f.Name, Valid: false})
		}
	}
	return out
}

// omit returns a copy of body without key.
func omit(body map[string]any, key string) map[string]any {
	out := make(map[string]any, len(body))
	for k, v := range body {
		if k != key {
			out[k] = v
		}
	}
	return out
}

// with returns a copy of body with key set to val.
func with(body map[string]any, key string, val any) map[string]any {
	out := make(map[string]any, len(body))
	for k, v := range body {
		out[k] = v
	}
	out[key] = val
	return out
}
