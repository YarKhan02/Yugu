package fuzz

import (
	"encoding/json"
	"strconv"
	"sync"
)

// Blackboard is the shared value store the fuzz workers read and write: the
// mechanism that carries an id a create returned into a later request that needs
// it (POST /assignments returns lessonId, GET /lessons/{lessonId} consumes it).
// It is concurrency-safe because the worker pool touches it in parallel.
type Blackboard struct {
	mu   sync.RWMutex
	vals map[string]string
}

// NewBlackboard returns an empty store.
func NewBlackboard() *Blackboard {
	return &Blackboard{vals: map[string]string{}}
}

// Put records a value under a key, overwriting any earlier one.
func (b *Blackboard) Put(key, val string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.vals[key] = val
}

// Get returns the value stored under key.
func (b *Blackboard) Get(key string) (string, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	v, ok := b.vals[key]
	return v, ok
}

// Learn extracts scalar fields from a JSON response body and records each by its
// key, so ids a write returned become available to later requests. It reads
// top-level fields and one level into a wrapping object ({"data":{"id":...}} or
// {"assignment":{"id":...}}), the common envelope shapes.
//
// shortcut: only scalars at depth 0 and 1 are learned; deeper nesting is
// ignored. Revisit if a target wraps ids more deeply.
func (b *Blackboard) Learn(body []byte) {
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		return // a non-object body (array, string, error page) carries no keyed ids
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, v := range top {
		if s, ok := scalar(v); ok {
			b.vals[k] = s
			continue
		}
		if nested, ok := v.(map[string]any); ok {
			for nk, nv := range nested {
				if s, ok := scalar(nv); ok {
					// A nested key wins only if the outer level did not set it.
					if _, exists := b.vals[nk]; !exists {
						b.vals[nk] = s
					}
				}
			}
		}
	}
}

// Resolve returns a value to fill a path parameter: an exact key match first,
// then a generic "id" fallback, since a read-back's item parameter is often
// named "id" while the create returned it under the same name.
func (b *Blackboard) Resolve(param string) (string, bool) {
	if v, ok := b.Get(param); ok {
		return v, true
	}
	return b.Get("id")
}

// scalar renders a JSON scalar (string or number) as a string, reporting false
// for objects, arrays, booleans and null, which are not id-like values.
func scalar(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case float64:
		// JSON numbers decode to float64; render ints without a trailing ".0".
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10), true
		}
		return strconv.FormatFloat(t, 'g', -1, 64), true
	default:
		return "", false
	}
}
