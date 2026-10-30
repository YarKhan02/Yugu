package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// FactKind enumerates the atomic observations the analyzers emit.
//
// Facts are the storage layer's source of truth; the graph is a projection
// over them (see graph.go). This matters because the inference rules that turn
// facts into graph edges and findings will change constantly during Phase 3,
// and re-deriving a graph from stored facts is cheap while re-parsing every
// analyzed project is not.
type FactKind string

const (
	// Schema facts.
	FactTable      FactKind = "table"
	FactColumn     FactKind = "column"
	FactPrimaryKey FactKind = "primary_key"
	FactForeignKey FactKind = "foreign_key"

	// Routing facts.
	FactRoute      FactKind = "route"
	FactMiddleware FactKind = "middleware"
	FactHandler    FactKind = "handler"

	// FactRequestSchema records the inputs an endpoint reads from the request
	// (body fields, path and query parameters). It is what the runtime fuzzer
	// consumes to build valid and invalid payloads; the static side produces it
	// so the fuzzer never parses source.
	FactRequestSchema FactKind = "request_schema"

	// Call graph facts.
	FactCallEdge FactKind = "call_edge"

	// Authorization facts. The distinction between these two is the whole
	// project: a candidate is a call that looks like an authorization check,
	// an enforcement fact is a proof that its result actually gates the
	// response.
	FactAuthCheckCandidate FactKind = "auth_check_candidate"
	FactAuthCheckEnforced  FactKind = "auth_check_enforced"

	// Data access facts.
	FactQuery          FactKind = "query"
	FactQueryPredicate FactKind = "query_predicate"

	// Response facts.
	FactResponseField FactKind = "response_field"

	// Identity facts: where the authenticated principal enters the handler.
	FactIdentitySource FactKind = "identity_source"
)

// ParamProvenance classifies where a query parameter's value came from. This
// is the pivot of IDOR detection: a request-derived value reaching a primary
// key predicate with no identity-derived predicate alongside it is the
// signature of an ownership failure.
type ParamProvenance string

const (
	// ProvenanceRequest is a value the caller controls: a path parameter,
	// query string, header or request body field.
	ProvenanceRequest ParamProvenance = "request"

	// ProvenanceIdentity is a value derived from the authenticated principal
	// and therefore not caller-controlled.
	ProvenanceIdentity ParamProvenance = "identity"

	// ProvenanceConstant is a literal in the source.
	ProvenanceConstant ParamProvenance = "constant"

	// ProvenanceDerived is computed from other values; Attrs should record
	// the contributing provenances.
	ProvenanceDerived ParamProvenance = "derived"

	// ProvenanceUnknown means value tracking failed. Treated as neither safe
	// nor unsafe; it produces an unverified fact, never a finding.
	ProvenanceUnknown ParamProvenance = "unknown"
)

// Fact is one atomic observation produced by an analyzer.
type Fact struct {
	// ID is assigned by storage.
	ID int64 `json:"id,omitempty"`

	// ScanID ties the fact to an immutable scan.
	ScanID string `json:"scan_id"`

	Kind FactKind `json:"kind"`

	// Subject is the fact's stable identity, independent of source position:
	// a normalized route ("GET /students/:id"), a qualified Go function name,
	// a database object name. Stability across revisions is what makes git
	// diffing possible, so Subject must never embed a line number.
	Subject string `json:"subject"`

	// Attrs carries kind-specific detail.
	Attrs map[string]any `json:"attrs,omitempty"`

	Evidence Evidence `json:"evidence"`
}

// Fingerprint is a content hash used to deduplicate facts within a scan.
// Attrs are serialized with sorted keys so the hash is stable.
func (f Fact) Fingerprint() string {
	h := sha256.New()
	h.Write([]byte(f.Kind))
	h.Write([]byte{0})
	h.Write([]byte(f.Subject))
	h.Write([]byte{0})
	h.Write([]byte(f.Evidence.Status))
	h.Write([]byte{0})
	h.Write([]byte(f.Evidence.UnresolvedReason))
	h.Write([]byte{0})

	if len(f.Attrs) > 0 {
		keys := make([]string, 0, len(f.Attrs))
		for k := range f.Attrs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			h.Write([]byte(k))
			h.Write([]byte{'='})
			v, _ := json.Marshal(f.Attrs[k])
			h.Write(v)
			h.Write([]byte{0})
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// RouteSubject builds the stable identity for a route. Patterns are
// normalized so that framework-specific parameter syntax does not cause a
// spurious diff between revisions.
func RouteSubject(method, pattern string) string {
	return strings.ToUpper(strings.TrimSpace(method)) + " " + NormalizeRoute(pattern)
}

// NormalizeRoute rewrites framework parameter syntax to a single form, so
// Gin's /students/:id, Chi's /students/{id} and Echo's /students/:id all share
// one identity.
func NormalizeRoute(pattern string) string {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		switch {
		case strings.HasPrefix(s, ":"):
			segs[i] = "{" + strings.TrimPrefix(s, ":") + "}"
		case strings.HasPrefix(s, "*"):
			segs[i] = "{*}"
		}
	}
	out := strings.Join(segs, "/")
	if len(out) > 1 {
		out = strings.TrimSuffix(out, "/")
	}
	return out
}
