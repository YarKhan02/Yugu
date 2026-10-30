package fuzz

import (
	"context"
	"fmt"
	"strings"
)

// validationAsymmetry is the cross-endpoint oracle: for a resource with both a
// create (POST collection) and an update (PUT/PATCH item), it omits a shared
// required field from each and reports a break when one endpoint rejects the
// omission (4xx) and the other accepts it (2xx). That inconsistency means a
// field's validation rule depends on which endpoint you go through — a gap a
// caller can slip bad data through.
//
// It runs after the main loop so update ids produced by creates are already on
// the blackboard. It needs an id to address the update; without one, the pair is
// left untested rather than guessed.
func validationAsymmetry(ctx context.Context, client Client, cfg RunConfig, bb *Blackboard) []Break {
	var out []Break
	for _, pair := range writeUpdatePairs(cfg.Endpoints) {
		create, update := pair[0], pair[1]
		if !selected(cfg.Selected, create) && !selected(cfg.Selected, update) {
			continue
		}
		pathVals, ok := resolvePathParams(update, bb)
		if !ok {
			continue // no id to address the update: cannot compare
		}

		for _, name := range sharedRequiredBodyFields(create, update) {
			cStatus := sendOmitting(ctx, client, create, nil, name, cfg.Token)
			uStatus := sendOmitting(ctx, client, update, pathVals, name, cfg.Token)
			if cStatus == 0 || uStatus == 0 {
				continue // a transport failure: cannot conclude
			}
			if is2xx(cStatus) != is2xx(uStatus) {
				out = append(out, Break{
					Endpoint: endpointKey(create) + " vs " + endpointKey(update),
					Kind:     BreakValidationAsymmetry,
					Payload:  "missing:" + name,
					Detail: fmt.Sprintf("omitting %q: %s returned %d, %s returned %d — one validates it, the other does not",
						name, endpointKey(create), cStatus, endpointKey(update), uStatus),
				})
			}
		}
	}
	return out
}

// sendOmitting fires a write at e with its baseline body minus one field and
// returns the status, or 0 on a transport error.
func sendOmitting(ctx context.Context, client Client, e Endpoint, pathVals map[string]string, field, token string) int {
	body := omit(baselineBody(e.Fields), field)
	resp, err := client.Send(ctx, Request{
		Method: e.Method, Path: e.Path, PathParams: pathVals, Body: body, Token: token,
	})
	if err != nil {
		return 0
	}
	return resp.Status
}

// baselineBody is the valid body for an endpoint's fields.
func baselineBody(fields []Field) map[string]any { return Payloads(fields)[0].Body }

// sharedRequiredBodyFields returns the names of body fields present on both
// endpoints that at least one of them marks required — the fields whose
// validation is worth comparing.
func sharedRequiredBodyFields(a, b Endpoint) []string {
	bf := bodyFields(b)
	var out []string
	for name, af := range bodyFields(a) {
		bfield, ok := bf[name]
		if !ok {
			continue
		}
		if af.Required || bfield.Required {
			out = append(out, name)
		}
	}
	return out
}

func bodyFields(e Endpoint) map[string]Field {
	m := map[string]Field{}
	for _, f := range e.Fields {
		if f.In == "body" {
			m[f.Name] = f
		}
	}
	return m
}

// writeUpdatePairs pairs each create (POST on a collection) with an update
// (PUT/PATCH on that collection's item path), matched by path like ReadBack.
func writeUpdatePairs(eps []Endpoint) [][2]Endpoint {
	var pairs [][2]Endpoint
	for _, c := range eps {
		if !strings.EqualFold(c.Method, "POST") {
			continue
		}
		cs := pathSegs(c.Path)
		if len(cs) > 0 && isParamSeg(cs[len(cs)-1]) {
			continue // POST on an item path is not a create
		}
		for _, u := range eps {
			if !strings.EqualFold(u.Method, "PUT") && !strings.EqualFold(u.Method, "PATCH") {
				continue
			}
			us := pathSegs(u.Path)
			if len(us) != len(cs)+1 || !isParamSeg(us[len(us)-1]) {
				continue
			}
			if segsMatch(cs, us[:len(cs)]) {
				pairs = append(pairs, [2]Endpoint{c, u})
				break
			}
		}
	}
	return pairs
}
