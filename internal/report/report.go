// Package report turns a scan's stored facts into a human view of the one
// question the tool exists to answer: which identities can reach which
// resources through which endpoints. It is a projection over facts, so it can
// be re-rendered at any time without re-analyzing the project.
package report

import (
	"sort"

	"github.com/YarKhan02/PathWise/internal/model"
)

// Report is the assembled, render-ready view of one scan.
type Report struct {
	Project      string
	ScanID       string
	SchemaSource string
	GeneratedAt  string

	Endpoints []Endpoint
	Roles     []string      // every role demanded by a gate, sorted
	Tables    []string      // every table reached, sorted
	Schema    []TableSchema // the database schema (columns + types), sorted by table

	RouteCount      int
	TableCount      int
	RoleCount       int
	FindingCount    int
	UnresolvedCount int
}

// Endpoint is one route and everything known about what it exposes.
type Endpoint struct {
	Method         string
	Path           string
	Subject        string
	Handler        string
	HandlerFile    string
	HandlerLine    int
	Roles          []string
	Middleware     []MiddlewareRef
	Checks         []CheckRef
	Resources      []Resource
	ResponseFields []string // JSON fields the handler serializes to the client
	Unresolved     bool
	Findings       []model.Finding
	// SessionEndReason, when set, is why this endpoint terminates the caller's
	// session (clears the auth cookie, or deletes the session row the auth path
	// reads). Runtime testing skips it by default so it does not invalidate the
	// credential the other scenarios run as.
	SessionEndReason string
}

// MiddlewareRef is one middleware in an endpoint's chain, with the constant
// arguments it was built with (RequireRole("admin") → Args ["admin"]).
type MiddlewareRef struct {
	Name string
	Args []string
}

// CheckRef is an authorization check call found in the handler and the verdict
// on whether it gates the response (enforced / discarded / non_dominating / …).
type CheckRef struct {
	Func        string
	Enforcement string
	File        string
	Line        int
}

// Resource is a table an endpoint reaches, the operations it performs on it,
// and the columns it reads, filters on and writes. Star and Ambiguous are the
// honest markers from column attribution: Star means a SELECT * read all
// columns, Ambiguous means a multi-table query referenced columns that could
// not be pinned to this table.
type Resource struct {
	Table         string
	Operations    []string
	ReadColumns   []string
	FilterColumns []string
	WriteColumns  []string
	Star          bool
	Ambiguous     bool
}

// TableSchema is one table's shape for the database view: its columns in
// declaration order, with their types.
type TableSchema struct {
	Name    string
	Columns []ColumnSchema
}

// ColumnSchema is one column's name, type and whether it is nullable or part of
// the primary key. ForeignKey, when set, is the "table.column" this column
// references.
type ColumnSchema struct {
	Name       string
	Type       string
	Nullable   bool
	PrimaryKey bool
	ForeignKey string
}

// Build assembles a report from a scan's route, middleware and query facts plus
// its findings. It takes facts rather than the store so it stays a pure
// projection, testable without a database.
func Build(project, scanID, schemaSource, generatedAt string,
	routes, middleware, queries, authChecks, tables, columns, responses, foreignKeys []model.Fact, findings []model.Finding) *Report {

	r := &Report{Project: project, ScanID: scanID, SchemaSource: schemaSource, GeneratedAt: generatedAt}

	// Endpoints, keyed by route subject, from the real route facts (those
	// carrying a method attribute; build-error and miss facts have none).
	bySubject := map[string]*Endpoint{}
	for _, f := range routes {
		method := attrStr(f.Attrs, "method")
		if method == "" {
			continue
		}
		ep := &Endpoint{
			Method:           method,
			Path:             attrStr(f.Attrs, "pattern"),
			Subject:          f.Subject,
			Handler:          attrStr(f.Attrs, "handler"),
			SessionEndReason: attrStr(f.Attrs, "session_terminating"),
		}
		if len(f.Evidence.Source) > 0 {
			ep.HandlerFile = f.Evidence.Source[0].File
			ep.HandlerLine = f.Evidence.Source[0].StartLine
		}
		bySubject[f.Subject] = ep
	}

	// Roles and the middleware chain come from the gate facts. Each middleware
	// fact carries its order in the chain and the constant args it was built
	// with; a role is such an arg (RequireRole("admin")).
	roleSet := map[string]bool{}
	mwByOrder := map[*Endpoint]map[int]MiddlewareRef{}
	for _, f := range middleware {
		ep := bySubject[attrStr(f.Attrs, "route")]
		if ep == nil {
			continue
		}
		args := attrStrings(f.Attrs, "args")
		if mwByOrder[ep] == nil {
			mwByOrder[ep] = map[int]MiddlewareRef{}
		}
		mwByOrder[ep][attrInt(f.Attrs, "order")] = MiddlewareRef{Name: f.Subject, Args: args}
		for _, role := range args {
			if !contains(ep.Roles, role) {
				ep.Roles = append(ep.Roles, role)
			}
			roleSet[role] = true
		}
	}
	for ep, byOrder := range mwByOrder {
		for i := 0; i < len(byOrder); i++ {
			if m, ok := byOrder[i]; ok {
				ep.Middleware = append(ep.Middleware, m)
			}
		}
	}

	// Authorization checks and their enforcement verdict.
	for _, f := range authChecks {
		ep := bySubject[attrStr(f.Attrs, "endpoint")]
		if ep == nil {
			continue
		}
		ref := CheckRef{Func: attrStr(f.Attrs, "check"), Enforcement: attrStr(f.Attrs, "enforcement")}
		if len(f.Evidence.Source) > 0 {
			ref.File = f.Evidence.Source[0].File
			ref.Line = f.Evidence.Source[0].StartLine
		}
		ep.Checks = append(ep.Checks, ref)
	}

	// Resources (and unresolved queries) come from the data-access facts.
	tableSet := map[string]bool{}
	for _, f := range queries {
		ep := bySubject[attrStr(f.Attrs, "endpoint")]
		if ep == nil {
			continue
		}
		if f.Evidence.Status == model.StatusUnverified {
			ep.Unresolved = true
			r.UnresolvedCount++
			continue
		}
		table := attrStr(f.Attrs, "table")
		if table == "" {
			continue
		}
		ep.Resources = append(ep.Resources, Resource{
			Table:         table,
			Operations:    attrStrings(f.Attrs, "operations"),
			ReadColumns:   attrStrings(f.Attrs, "read_columns"),
			FilterColumns: attrStrings(f.Attrs, "filter_columns"),
			WriteColumns:  attrStrings(f.Attrs, "write_columns"),
			Star:          attrBool(f.Attrs, "columns_star"),
			Ambiguous:     attrBool(f.Attrs, "columns_ambiguous"),
		})
		tableSet[table] = true
	}

	// Response fields the handler serializes, per endpoint.
	for _, f := range responses {
		if ep := bySubject[attrStr(f.Attrs, "endpoint")]; ep != nil {
			ep.ResponseFields = attrStrings(f.Attrs, "fields")
		}
	}

	for _, f := range findings {
		if ep := bySubject[f.Endpoint]; ep != nil {
			ep.Findings = append(ep.Findings, f)
		}
	}

	for _, ep := range bySubject {
		sort.Strings(ep.Roles)
		sort.Slice(ep.Resources, func(i, j int) bool { return ep.Resources[i].Table < ep.Resources[j].Table })
		sort.Slice(ep.Checks, func(i, j int) bool { return ep.Checks[i].Func < ep.Checks[j].Func })
		r.Endpoints = append(r.Endpoints, *ep)
	}
	sort.Slice(r.Endpoints, func(i, j int) bool { return r.Endpoints[i].Subject < r.Endpoints[j].Subject })

	r.Schema = buildSchema(tables, columns, foreignKeys)
	r.Roles = sortedKeys(roleSet)
	r.Tables = sortedKeys(tableSet)
	r.RouteCount = len(r.Endpoints)
	r.TableCount = len(r.Tables)
	r.RoleCount = len(r.Roles)
	r.FindingCount = len(findings)
	return r
}

// buildSchema assembles the table-by-table column view from the schema facts:
// FactTable carries each table's column order and primary key, FactColumn each
// column's type and nullability (subject "table.column").
func buildSchema(tables, columns, foreignKeys []model.Fact) []TableSchema {
	type colMeta struct {
		typ      string
		nullable bool
	}
	meta := map[string]colMeta{} // "table.column" -> type/nullable
	for _, f := range columns {
		meta[f.Subject] = colMeta{typ: attrStr(f.Attrs, "type"), nullable: attrBool(f.Attrs, "nullable")}
	}
	fkRef := map[string]string{} // "from_table.from_column" -> "to_table.to_column"
	for _, f := range foreignKeys {
		from := attrStr(f.Attrs, "from_table") + "." + attrStr(f.Attrs, "from_column")
		fkRef[from] = attrStr(f.Attrs, "to_table") + "." + attrStr(f.Attrs, "to_column")
	}

	var out []TableSchema
	for _, f := range tables {
		ts := TableSchema{Name: f.Subject}
		pk := map[string]bool{}
		for _, c := range attrStrings(f.Attrs, "primary_key") {
			pk[c] = true
		}
		for _, name := range attrStrings(f.Attrs, "columns") {
			m := meta[f.Subject+"."+name]
			ts.Columns = append(ts.Columns, ColumnSchema{
				Name: name, Type: m.typ, Nullable: m.nullable, PrimaryKey: pk[name],
				ForeignKey: fkRef[f.Subject+"."+name],
			})
		}
		out = append(out, ts)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func attrBool(attrs map[string]any, key string) bool {
	if attrs == nil {
		return false
	}
	b, _ := attrs[key].(bool)
	return b
}

func attrStr(attrs map[string]any, key string) string {
	if attrs == nil {
		return ""
	}
	if s, ok := attrs[key].(string); ok {
		return s
	}
	return ""
}

// attrInt reads an integer attribute, tolerating the float64 a JSON round-trip
// turns it into.
func attrInt(attrs map[string]any, key string) int {
	if attrs == nil {
		return 0
	}
	switch v := attrs[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return 0
}

// attrStrings reads a []string attribute that round-tripped through JSON as
// []any of strings.
func attrStrings(attrs map[string]any, key string) []string {
	if attrs == nil {
		return nil
	}
	switch v := attrs[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
