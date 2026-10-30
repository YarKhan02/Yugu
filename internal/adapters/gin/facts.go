package gin

import (
	"strings"

	"golang.org/x/tools/go/ssa"

	"github.com/YarKhan02/PathWise/internal/model"
)

// Facts converts a discovery result into the shared model's facts, tied to one
// scan. Routes become code_confirmed facts; misses become unverified facts that
// name why discovery stopped, so a gap in route coverage is recorded rather
// than mistaken for an application that has no such route.
func Facts(scanID string, res *Result) []model.Fact {
	facts := make([]model.Fact, 0, len(res.Routes)+len(res.Misses))

	for _, r := range res.Routes {
		loc := model.SourceLocation{File: r.Pos.Filename, StartLine: r.Pos.Line, EndLine: r.Pos.Line}
		subject := r.Subject()

		attrs := map[string]any{
			"method":  r.Method,
			"pattern": model.NormalizeRoute(r.Pattern),
			"handler": r.Handler,
		}
		if len(r.Middleware) > 0 {
			attrs["middleware"] = r.MiddlewareNames()
		}
		facts = append(facts, model.Fact{
			ScanID:   scanID,
			Kind:     model.FactRoute,
			Subject:  subject,
			Attrs:    attrs,
			Evidence: model.CodeConfirmed("gin route registration", loc),
		})

		if r.Handler != "" {
			facts = append(facts, model.Fact{
				ScanID:   scanID,
				Kind:     model.FactHandler,
				Subject:  r.Handler,
				Attrs:    map[string]any{"route": subject},
				Evidence: model.CodeConfirmed("handler bound to route "+subject, loc),
			})
		}

		// One middleware fact per entry, carrying its position in the chain and
		// the constant arguments it was built with, so Phase 3 can attach an
		// enforcement proof to the right link and a reader can see the role a
		// RequireRole("...") gate demands.
		for i, m := range r.Middleware {
			mattrs := map[string]any{"route": subject, "order": i}
			if len(m.Args) > 0 {
				mattrs["args"] = m.Args
			}
			facts = append(facts, model.Fact{
				ScanID:   scanID,
				Kind:     model.FactMiddleware,
				Subject:  m.Name,
				Attrs:    mattrs,
				Evidence: model.CodeConfirmed("middleware guarding route "+subject, loc),
			})
		}
	}

	for _, m := range res.Misses {
		loc := model.SourceLocation{File: m.Pos.Filename, StartLine: m.Pos.Line, EndLine: m.Pos.Line}
		facts = append(facts, model.Fact{
			ScanID:   scanID,
			Kind:     model.FactRoute,
			Subject:  "unresolved route at " + m.Pos.String(),
			Evidence: model.Unresolved(m.Reason, m.Detail, loc),
		})
	}

	return facts
}

// SchemaFacts emits one request-schema fact per route whose inputs could be
// recovered. The schema unions the path parameters declared in the route
// pattern with the body fields and parameters the handler actually reads, so
// the fuzzer sees every input an endpoint takes even when the handler ignores a
// declared path parameter. funcs resolves a route's handler name to its SSA
// function; an unresolved handler is recorded as an unknown, not dropped.
func SchemaFacts(scanID string, routes []Route, funcs map[string]*ssa.Function) []model.Fact {
	var facts []model.Fact
	for _, r := range routes {
		fn := funcs[r.Handler]
		schema := mergePatternParams(HandlerSchema(fn), r.Pattern)
		if fn == nil && r.Handler != "" {
			schema.Unknown = append(schema.Unknown, "handler "+r.Handler+" unresolved; request body shape unknown")
		}
		if len(schema.Fields) == 0 && len(schema.Unknown) == 0 {
			continue // nothing to say about this endpoint's inputs
		}

		fields := make([]map[string]any, len(schema.Fields))
		for i, f := range schema.Fields {
			fields[i] = map[string]any{"name": f.Name, "in": f.In, "goType": f.GoType, "required": f.Required}
		}
		attrs := map[string]any{"fields": fields}
		if len(schema.Unknown) > 0 {
			attrs["unknown"] = schema.Unknown
		}
		loc := model.SourceLocation{File: r.Pos.Filename, StartLine: r.Pos.Line, EndLine: r.Pos.Line}
		facts = append(facts, model.Fact{
			ScanID:   scanID,
			Kind:     model.FactRequestSchema,
			Subject:  r.Subject(),
			Attrs:    attrs,
			Evidence: model.CodeConfirmed("request inputs read by handler "+r.Handler, loc),
		})
	}
	return facts
}

// mergePatternParams adds the path parameters declared in a normalized route
// pattern ("/students/{id}") that the handler walk did not already record. A
// handler may validate a path parameter without ever calling c.Param for it, so
// the pattern is the authoritative source for which path parameters exist.
func mergePatternParams(s RequestSchema, pattern string) RequestSchema {
	have := map[string]bool{}
	for _, f := range s.Fields {
		if f.In == "path" {
			have[f.Name] = true
		}
	}
	for _, seg := range strings.Split(pattern, "/") {
		if len(seg) < 3 || seg[0] != '{' || seg[len(seg)-1] != '}' {
			continue
		}
		name := seg[1 : len(seg)-1]
		if name == "*" || have[name] { // {*} is a nameless catch-all, not a param
			continue
		}
		have[name] = true
		s.Fields = append(s.Fields, RequestField{Name: name, In: "path", GoType: "string"})
	}
	return s
}
