package fuzz

import "testing"

func TestBlackboardLearnAndResolve(t *testing.T) {
	b := NewBlackboard()
	// A create that returns a top-level id and a camelCase foreign id.
	b.Learn([]byte(`{"id": 42, "lessonId": "L7", "name": "algebra"}`))

	if v, ok := b.Get("id"); !ok || v != "42" {
		t.Errorf("id = %q,%v, want 42", v, ok)
	}
	if v, ok := b.Get("lessonId"); !ok || v != "L7" {
		t.Errorf("lessonId = %q,%v, want L7", v, ok)
	}

	// Resolve falls back to "id" for an item parameter named otherwise.
	if v, ok := b.Resolve("assignmentId"); !ok || v != "42" {
		t.Errorf("Resolve(assignmentId) = %q,%v, want fallback to id 42", v, ok)
	}
	if v, ok := b.Resolve("lessonId"); !ok || v != "L7" {
		t.Errorf("Resolve(lessonId) = %q,%v, want exact L7", v, ok)
	}
}

// TestBlackboardLearnNested covers the common {"data":{...}} envelope.
func TestBlackboardLearnNested(t *testing.T) {
	b := NewBlackboard()
	b.Learn([]byte(`{"data": {"id": 99}}`))
	if v, ok := b.Get("id"); !ok || v != "99" {
		t.Errorf("nested id = %q,%v, want 99", v, ok)
	}
}

// TestBlackboardLearnNonObject is the negative control: a non-object body must
// not panic or invent keys.
func TestBlackboardLearnNonObject(t *testing.T) {
	b := NewBlackboard()
	b.Learn([]byte(`[1,2,3]`))
	b.Learn([]byte(`not json`))
	if _, ok := b.Get("id"); ok {
		t.Errorf("non-object bodies must not populate the blackboard")
	}
}

func TestReadBack(t *testing.T) {
	all := []Endpoint{
		{Method: "POST", Path: "/assignments"},
		{Method: "GET", Path: "/assignments"},        // list, not a read-back
		{Method: "GET", Path: "/assignments/{id}"},   // the read-back
		{Method: "GET", Path: "/lessons/{lessonId}"}, // unrelated resource
	}

	// Create pairs with the item GET of the same collection.
	if g, ok := ReadBack(Endpoint{Method: "POST", Path: "/assignments"}, all); !ok || g.Path != "/assignments/{id}" {
		t.Errorf("create read-back = %q,%v, want GET /assignments/{id}", g.Path, ok)
	}
	// Update (already an item path) pairs with the same item GET.
	if g, ok := ReadBack(Endpoint{Method: "PATCH", Path: "/assignments/{id}"}, all); !ok || g.Path != "/assignments/{id}" {
		t.Errorf("update read-back = %q,%v, want GET /assignments/{id}", g.Path, ok)
	}
	if p := ReadBackParam(Endpoint{Path: "/assignments/{id}"}); p != "id" {
		t.Errorf("ReadBackParam = %q, want id", p)
	}

	// Negative control: a resource with no item GET has no read-back.
	noItem := []Endpoint{{Method: "POST", Path: "/events"}, {Method: "GET", Path: "/events"}}
	if g, ok := ReadBack(Endpoint{Method: "POST", Path: "/events"}, noItem); ok {
		t.Errorf("want no read-back for /events, got %q", g.Path)
	}
}
