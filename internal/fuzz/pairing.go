package fuzz

import "strings"

// Endpoint is one route the fuzzer can exercise: its method, normalized path
// ({param} form), and the request inputs recovered for it.
type Endpoint struct {
	Method string
	Path   string
	Fields []Field
}

// ReadBack returns the GET endpoint that reads back the resource a write
// endpoint touches, matched by path, so a write can be verified by reading it.
// The read-back is a GET on the item path — the write's collection followed by
// exactly one parameter segment (POST /assignments → GET /assignments/{id}) —
// or the write's own item path for an update or delete. It reports false when
// no such GET exists, leaving the write unverifiable rather than guessing.
func ReadBack(write Endpoint, all []Endpoint) (Endpoint, bool) {
	coll := collectionSegs(write.Path)
	for _, g := range all {
		if !strings.EqualFold(g.Method, "GET") {
			continue
		}
		item := pathSegs(g.Path)
		if len(item) != len(coll)+1 || !isParamSeg(item[len(item)-1]) {
			continue // a read-back is the collection plus one id segment
		}
		if segsMatch(coll, item[:len(coll)]) {
			return g, true
		}
	}
	return Endpoint{}, false
}

// ReadBackParam returns the name of a read-back endpoint's item parameter (the
// trailing {name}), which the engine resolves against the blackboard.
func ReadBackParam(readBack Endpoint) string {
	segs := pathSegs(readBack.Path)
	if len(segs) == 0 {
		return ""
	}
	return strings.Trim(segs[len(segs)-1], "{}")
}

// collectionSegs returns the collection path of a write: its segments with a
// trailing parameter (an item path like /x/{id}) dropped, so create and update
// on the same resource share one collection.
func collectionSegs(p string) []string {
	segs := pathSegs(p)
	if len(segs) > 0 && isParamSeg(segs[len(segs)-1]) {
		return segs[:len(segs)-1]
	}
	return segs
}

func pathSegs(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func isParamSeg(s string) bool {
	return strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")
}

// segsMatch reports whether two segment lists are equal, treating any two
// parameter segments as equal (their names need not match).
func segsMatch(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if isParamSeg(a[i]) && isParamSeg(b[i]) {
			continue
		}
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
}
