package fuzz

import (
	"context"
	"encoding/json"
	"strings"
)

// RunConfig is one fuzz run: the endpoints discovered for the target, the bearer
// token to act with (supplied per run, never persisted), and which endpoints to
// exercise. An empty Selected means every write endpoint.
//
// shortcut: execution is sequential. The blackboard is already concurrency-safe,
// so a bounded worker pool is a drop-in once run time matters; correctness, not
// throughput, is what this first version establishes.
type RunConfig struct {
	Endpoints []Endpoint
	Token     string
	Selected  map[string]bool // "METHOD /path" keys; empty = all write endpoints
	Mutator   Mutator         // optional adversarial-value source (e.g. Ollama); nil = deterministic only
}

// Break is one reported behavioral inconsistency: which endpoint and payload
// produced it, and the oracle's reason.
type Break struct {
	Endpoint string
	Kind     BreakKind
	Payload  string
	Detail   string
}

// Run fuzzes the selected write endpoints and returns the breaks found. Writes
// run before deletes so a resource is exercised (created, read, updated) before
// it is destroyed, and deletes act only on ids earlier writes produced — the
// blackboard holds those ids, so a DELETE never targets fixture data.
func Run(ctx context.Context, client Client, cfg RunConfig) []Break {
	bb := NewBlackboard()
	var breaks []Break

	for _, e := range ordered(cfg.Endpoints) {
		if !selected(cfg.Selected, e) {
			continue
		}
		pathVals, ok := resolvePathParams(e, bb)
		if !ok {
			continue // an item write with no id to target yet — nothing to conclude
		}
		readBack, hasReadBack := ReadBack(e, cfg.Endpoints)

		for _, p := range PayloadsWith(ctx, e.Fields, cfg.Mutator) {
			req := Request{
				Method: e.Method, Path: e.Path,
				PathParams: pathVals, Token: cfg.Token,
			}
			if methodHasBody(e.Method) {
				req.Body = p.Body
			}
			write, err := client.Send(ctx, req)
			if err != nil {
				continue // transport failure: cannot conclude, do not invent a break
			}
			if is2xx(write.Status) && methodHasBody(e.Method) {
				bb.Learn(write.Body) // make created ids available to later endpoints
			}

			obs := Observation{Expected: p, WriteStatus: write.Status}
			if write.Status >= 500 {
				// Confirm a server error reproduces before calling it a crash.
				if again, err := client.Send(ctx, req); err == nil {
					obs.WriteReproduced = again.Status >= 500
				}
			}
			if hasReadBack && is2xx(write.Status) {
				obs.ReadStatus, obs.ReadBackMatches = readResource(ctx, client, readBack, pathVals, write.Body, p)
			}

			if kind, detail := Classify(obs); kind != BreakNone {
				breaks = append(breaks, Break{Endpoint: endpointKey(e), Kind: kind, Payload: p.Label, Detail: detail})
			}
		}
	}

	// Cross-endpoint pass: compare create-vs-update validation now that the main
	// loop has populated the blackboard with ids to address updates.
	breaks = append(breaks, validationAsymmetry(ctx, client, cfg, bb)...)
	return breaks
}

// readResource reads the written resource back and reports the read status and,
// for a valid payload, whether the response reflected what was written.
func readResource(ctx context.Context, client Client, rb Endpoint, writePath map[string]string, writeBody []byte, p Payload) (status int, matches bool) {
	param := ReadBackParam(rb)
	id := writePath[param] // an update/delete carried the id in its own path
	if id == "" {
		id = idFromBody(writeBody, param) // a create returned it in the body
	}
	if id == "" {
		return 0, true // no id to read back with; leave the write unverified
	}
	resp, err := client.Send(ctx, Request{Method: "GET", Path: rb.Path, PathParams: map[string]string{param: id}})
	if err != nil {
		return 0, true
	}
	matches = true
	if p.Valid {
		matches = readBackReflects(p.Body, resp.Body)
	}
	return resp.Status, matches
}

// ordered puts non-delete writes first and deletes last, and drops read-only
// methods — the fuzzer mutates, then verifies with reads it issues itself.
func ordered(eps []Endpoint) []Endpoint {
	var writes, deletes []Endpoint
	for _, e := range eps {
		switch strings.ToUpper(e.Method) {
		case "POST", "PUT", "PATCH":
			writes = append(writes, e)
		case "DELETE":
			deletes = append(deletes, e)
		}
	}
	return append(writes, deletes...)
}

func selected(sel map[string]bool, e Endpoint) bool {
	return len(sel) == 0 || sel[endpointKey(e)]
}

func endpointKey(e Endpoint) string { return strings.ToUpper(e.Method) + " " + e.Path }

func methodHasBody(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

// resolvePathParams fills an endpoint's path parameters from the blackboard. A
// create has none and resolves trivially; an item write with an unresolvable id
// reports false so the caller skips it rather than firing at a guessed id.
func resolvePathParams(e Endpoint, bb *Blackboard) (map[string]string, bool) {
	out := map[string]string{}
	for _, f := range e.Fields {
		if f.In != "path" {
			continue
		}
		v, ok := bb.Resolve(f.Name)
		if !ok {
			return nil, false
		}
		out[f.Name] = v
	}
	return out, true
}

func idFromBody(body []byte, param string) string {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return ""
	}
	if v, ok := lookupScalar(m, param); ok {
		return v
	}
	if v, ok := lookupScalar(m, "id"); ok {
		return v
	}
	return ""
}

// readBackReflects reports whether a read-back response reflects the values a
// valid write sent.
//
// shortcut: it flags a drop only when NONE of the sent scalar fields appear in
// the response, not per-field. A per-field check would false-positive on
// write-only fields a read endpoint legitimately omits (a password). Upgrade to
// field-level once write-only fields are declared.
func readBackReflects(sent map[string]any, body []byte) bool {
	var got map[string]any
	if json.Unmarshal(body, &got) != nil {
		return true // unverifiable response shape: do not accuse
	}
	sentScalars, reflected := 0, 0
	for k, v := range sent {
		sv, ok := scalar(v)
		if !ok {
			continue
		}
		sentScalars++
		if gv, ok := lookupScalar(got, k); ok && gv == sv {
			reflected++
		}
	}
	return sentScalars == 0 || reflected > 0
}

// lookupScalar finds a scalar field by key at the top level or one level into a
// wrapping object, matching how Blackboard.Learn reads ids.
func lookupScalar(m map[string]any, key string) (string, bool) {
	if s, ok := scalar(m[key]); ok {
		return s, true
	}
	for _, v := range m {
		if nested, ok := v.(map[string]any); ok {
			if s, ok := scalar(nested[key]); ok {
				return s, true
			}
		}
	}
	return "", false
}
