// Package runtime verifies a scan's static conclusions against a running
// application. It exercises endpoints as developer-supplied identities and
// compares what the app actually did with what the analysis predicted. A
// disagreement where a protected endpoint turns out reachable is the
// highest-confidence signal PathWise produces.
//
// Runtime results never overwrite static conclusions; they are reported beside
// them. Safety is conservative by construction: only GET is executed, and an
// endpoint whose inputs are unknown (a path parameter) is left unverified
// rather than called with a fabricated value.
package runtime

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxBodyCapture bounds how much of a response body is read back for the
// dashboard. It is a preview of what the endpoint returned (the evidence of a
// leak on a divergent result), not a full capture, and it is never persisted.
const maxBodyCapture = 8 << 10 // 8 KiB

// Identity is a principal to test as. Role is the label the scan's role gates
// are compared against; Token is sent as a bearer credential and never stored.
type Identity struct {
	Role  string `json:"role"`
	Token string `json:"-"` // a credential: never serialized into any output
}

// Endpoint is the subset of a scanned route runtime testing needs.
type Endpoint struct {
	Method string
	Path   string
	Roles  []string // roles the static analysis found gating this endpoint
	// SessionEndReason, when set, means the endpoint terminates the caller's
	// session (a logout and the like). It is skipped by default so it does not
	// invalidate the credential later scenarios run as; opt in with --allow.
	SessionEndReason string
}

// Outcome is the verdict for one scenario.
type Outcome string

const (
	// Pass: observed behavior matched the static prediction.
	OutcomePass Outcome = "pass"
	// Fail: the analysis predicted reachable, the app denied it.
	OutcomeFail Outcome = "fail"
	// Divergent: the analysis predicted protected, the app served it anyway —
	// the strongest finding the tool can make.
	OutcomeDivergent Outcome = "divergent"
	// Blocked: the safety classifier refused to execute it (a non-GET method
	// without explicit opt-in). A policy decision, not an analysis gap — the
	// test could run, we chose not to fire it.
	OutcomeBlocked Outcome = "blocked"
	// Unverified: could not be concluded (a path parameter with no known value,
	// or a network error). Distinct from blocked: here the analysis, not policy,
	// is what stopped us — and distinct from "safe", which it must never imply.
	OutcomeUnverified Outcome = "unverified"
)

// Scenario is one (endpoint, identity) test and its static expectation. Skip,
// when set, carries why the scenario is not executed; SkipOutcome says whether
// that is a safety block or an analysis gap.
type Scenario struct {
	Method        string   `json:"method"`
	Path          string   `json:"path"`
	Identity      Identity `json:"identity"`
	ExpectAllowed bool     `json:"expectAllowed"`
	Skip          string   `json:"skip,omitempty"`        // why the scenario was not executed
	SkipOutcome   Outcome  `json:"skipOutcome,omitempty"` // blocked or unverified when Skip is set
}

// Result is a scenario after execution.
type Result struct {
	Scenario
	Status  int     `json:"status"`
	Outcome Outcome `json:"outcome"`
	Detail  string  `json:"detail"`
	// Body is a capped preview of the response the app returned — the data a
	// divergent result actually leaked. It is shown live and never persisted,
	// because a response body can carry sensitive data.
	Body string `json:"body,omitempty"`
}

// Plan builds the scenarios for a set of endpoints and identities. A non-GET
// method or a parameterized path is planned but marked skip, so the report
// shows it was considered and why it was not run.
//
// allowed opts specific endpoints into execution despite the deny-by-default
// safety policy. Its keys are "METHOD /path" (see Key); a non-GET endpoint
// absent from it is blocked. Opt-in is explicit and per-endpoint because
// executing a mutating request has real side effects — an endpoint that deletes
// records is not safe to fire merely because the app is running locally.
func Plan(endpoints []Endpoint, identities []Identity, allowed map[string]bool) []Scenario {
	var out []Scenario
	for _, e := range endpoints {
		skip, skipOutcome := "", Outcome("")
		switch {
		case e.SessionEndReason != "" && !allowed[Key(e.Method, e.Path)]:
			// Firing a logout-like endpoint would invalidate the token every other
			// scenario runs as, so it is skipped unless explicitly opted in.
			skip, skipOutcome = "session-terminating: "+e.SessionEndReason+" (safety: opt-in with --allow)", OutcomeBlocked
		case !strings.EqualFold(e.Method, "GET") && !allowed[Key(e.Method, e.Path)]:
			skip, skipOutcome = "non-GET method is not executed (safety: opt-in with --allow)", OutcomeBlocked
		case strings.ContainsAny(e.Path, "{:*"):
			skip, skipOutcome = "path parameter — no known valid value, left unverified", OutcomeUnverified
		}
		for _, id := range identities {
			out = append(out, Scenario{
				Method:        e.Method,
				Path:          e.Path,
				Identity:      id,
				ExpectAllowed: expectAllowed(e, id),
				Skip:          skip,
				SkipOutcome:   skipOutcome,
			})
		}
	}
	return out
}

// Key is the stable "METHOD /path" identity used for opt-in lookups.
func Key(method, path string) string {
	return strings.ToUpper(method) + " " + path
}

// expectAllowed is the static prediction: an identity may reach an endpoint when
// the endpoint demands no role, or demands a role the identity holds.
func expectAllowed(e Endpoint, id Identity) bool {
	if len(e.Roles) == 0 {
		return true
	}
	for _, r := range e.Roles {
		if strings.EqualFold(r, id.Role) {
			return true
		}
	}
	return false
}

// Run executes the runnable scenarios against baseURL and classifies each.
func Run(ctx context.Context, baseURL string, scenarios []Scenario, client *http.Client) []Result {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	base := strings.TrimRight(baseURL, "/")
	out := make([]Result, 0, len(scenarios))
	for _, s := range scenarios {
		r := Result{Scenario: s}
		if s.Skip != "" {
			r.Outcome, r.Detail = s.SkipOutcome, s.Skip
			out = append(out, r)
			continue
		}
		req, err := http.NewRequestWithContext(ctx, strings.ToUpper(s.Method), base+s.Path, nil)
		if err != nil {
			r.Outcome, r.Detail = OutcomeUnverified, "build request: "+err.Error()
			out = append(out, r)
			continue
		}
		if s.Identity.Token != "" {
			req.Header.Set("Authorization", "Bearer "+s.Identity.Token)
		}
		resp, err := client.Do(req)
		if err != nil {
			r.Outcome, r.Detail = OutcomeUnverified, "request failed: "+err.Error()
			out = append(out, r)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyCapture))
		resp.Body.Close()
		r.Status = resp.StatusCode
		r.Body = string(body)
		r.Outcome, r.Detail = classify(s.ExpectAllowed, resp.StatusCode)
		out = append(out, r)
	}
	return out
}

// classify compares the static expectation with the observed HTTP status.
func classify(expectAllowed bool, status int) (Outcome, string) {
	allowed := status >= 200 && status < 300
	denied := status == http.StatusUnauthorized || status == http.StatusForbidden
	switch {
	case !allowed && !denied:
		return OutcomeUnverified, fmt.Sprintf("status %d is neither clearly allowed nor denied", status)
	case expectAllowed && allowed:
		return OutcomePass, fmt.Sprintf("reachable as predicted (%d)", status)
	case !expectAllowed && denied:
		return OutcomePass, fmt.Sprintf("denied as predicted (%d)", status)
	case !expectAllowed && allowed:
		return OutcomeDivergent, fmt.Sprintf("predicted protected, but served %d to an identity without the required role", status)
	default: // expectAllowed && denied
		return OutcomeFail, fmt.Sprintf("predicted reachable, but the app denied it (%d)", status)
	}
}
