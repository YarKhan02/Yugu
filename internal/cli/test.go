package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/YarKhan02/PathWise/internal/project"
	"github.com/YarKhan02/PathWise/internal/report"
	"github.com/YarKhan02/PathWise/internal/runtime"
	"github.com/YarKhan02/PathWise/internal/storage/sqlite"
)

func newTestCommand(g *globalFlags) *cobra.Command {
	var (
		baseURL    string
		identities []string
		allow      []string
		format     string
		noStore    bool
	)

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run runtime authorization tests against a running application",
		Long: `Test executes the scenarios implied by the latest scan against a live
application and records what actually happened.

For each endpoint it predicted a role gate for, Test sends a request as each
supplied identity and compares the response to that prediction. Runtime results
never overwrite static conclusions. Where the two disagree, the divergence is
its own result: a static "protected" that a live request defeated is the
strongest signal PathWise can produce.

Safety is conservative by construction. Only GET is executed; every other
method defaults to denied and must be opted into per endpoint with --allow,
because a mutating request has real side effects. An endpoint with a path
parameter is left unverified rather than called with a fabricated value.
Credentials are supplied by the developer and never persisted.

Results are recorded against the scan (unless --no-store) so the dashboard can
show them beside the static conclusions — stored apart, never merged.`,
		Example: `  pathwise test --base-url http://localhost:8080 \
    --identity student=<token> --identity admin=<token> \
    --allow "POST /batches"`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTest(cmd.Context(), cmd, g, testFlags{
				baseURL: baseURL, identities: identities, allow: allow,
				format: format, noStore: noStore,
			})
		},
	}

	f := cmd.Flags()
	f.StringVar(&baseURL, "base-url", "", "base URL of the running application (required)")
	f.StringArrayVar(&identities, "identity", nil,
		"identity as role=token (repeatable); the role is matched against the scan's gates, tokens are never persisted")
	f.StringArrayVar(&allow, "allow", nil,
		`opt a non-GET endpoint into execution as "METHOD /path" (repeatable); it has real side effects`)
	f.StringVar(&format, "format", "text", "output format: text|json")
	f.BoolVar(&noStore, "no-store", false, "do not record results against the scan")
	return cmd
}

// testFlags groups the test command's inputs so runTest keeps one argument list.
type testFlags struct {
	baseURL    string
	identities []string
	allow      []string
	format     string
	noStore    bool
}

func runTest(ctx context.Context, cmd *cobra.Command, g *globalFlags, fl testFlags) error {
	if strings.TrimSpace(fl.baseURL) == "" {
		return fmt.Errorf("--base-url is required: point it at the running application to test")
	}
	if fl.format != "text" && fl.format != "json" {
		return fmt.Errorf("unknown --format %q: want text or json", fl.format)
	}
	identities, err := parseIdentities(fl.identities)
	if err != nil {
		return err
	}
	if len(identities) == 0 {
		return fmt.Errorf("at least one --identity role=token is required")
	}
	allowed, err := parseAllow(fl.allow)
	if err != nil {
		return err
	}

	proj, err := project.Resolve(g.projectDir)
	if err != nil {
		return err
	}
	storePath, err := g.resolveStorePath(proj.Root)
	if err != nil {
		return err
	}
	store, err := sqlite.Open(ctx, storePath)
	if err != nil {
		return err
	}
	defer store.Close()

	stored, err := store.UpsertProject(ctx, filepath.Base(proj.Root), proj.Root, proj.ModulePath)
	if err != nil {
		return err
	}
	scan, err := store.LatestScan(ctx, stored.ID)
	if err != nil {
		return err
	}
	if scan == nil {
		return fmt.Errorf("no scan found for %s — run `pathwise scan` first", stored.Name)
	}
	rep, err := loadReport(ctx, store, scan, stored.Name)
	if err != nil {
		return err
	}

	scenarios := runtime.Plan(endpointsForRuntime(rep), identities, allowed)
	results := runtime.Run(ctx, fl.baseURL, scenarios, nil)

	if !fl.noStore {
		if _, err := store.InsertTestResults(ctx, scan.ID, toStoredResults(results)); err != nil {
			return fmt.Errorf("record test results: %w", err)
		}
	}

	out := cmd.OutOrStdout()
	if fl.format == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}
	writeTestText(out, fl.baseURL, stored.Name, results)
	return nil
}

// parseAllow reads the repeatable --allow flag into a set runtime.Plan accepts,
// keyed by the stable "METHOD /path" identity.
func parseAllow(raw []string) (map[string]bool, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(map[string]bool, len(raw))
	for _, s := range raw {
		method, path, ok := strings.Cut(strings.TrimSpace(s), " ")
		if !ok || method == "" || !strings.HasPrefix(path, "/") {
			return nil, fmt.Errorf("invalid --allow %q: want \"METHOD /path\"", s)
		}
		out[runtime.Key(method, path)] = true
	}
	return out, nil
}

// toStoredResults maps runtime results onto the storage record. The safety class
// is derived from the outcome: a blocked result is one the classifier denied.
func toStoredResults(results []runtime.Result) []sqlite.TestResult {
	out := make([]sqlite.TestResult, 0, len(results))
	for _, r := range results {
		expectation := "blocked"
		if r.ExpectAllowed {
			expectation = "allowed"
		}
		safety := "allow"
		if r.Outcome == runtime.OutcomeBlocked {
			safety = "deny"
		}
		out = append(out, sqlite.TestResult{
			Method: r.Method, Path: r.Path, IdentityRole: r.Identity.Role,
			Expectation: expectation, SafetyClass: safety,
			Outcome: string(r.Outcome), StatusCode: r.Status, Detail: r.Detail, Body: r.Body,
		})
	}
	return out
}

// parseIdentities reads the repeatable role=token flag. The role labels the
// principal and is compared against the role a gate demands; the token is the
// credential and is kept only in memory for the duration of the run.
func parseIdentities(raw []string) ([]runtime.Identity, error) {
	out := make([]runtime.Identity, 0, len(raw))
	for _, s := range raw {
		role, token, ok := strings.Cut(s, "=")
		role, token = strings.TrimSpace(role), strings.TrimSpace(token)
		if !ok || role == "" || token == "" {
			return nil, fmt.Errorf("invalid --identity %q: want role=token", s)
		}
		out = append(out, runtime.Identity{Role: role, Token: token})
	}
	return out, nil
}

// endpointsForRuntime projects the scanned report onto the slice runtime needs.
func endpointsForRuntime(rep *report.Report) []runtime.Endpoint {
	eps := make([]runtime.Endpoint, 0, len(rep.Endpoints))
	for _, e := range rep.Endpoints {
		eps = append(eps, runtime.Endpoint{Method: e.Method, Path: e.Path, Roles: e.Roles, SessionEndReason: e.SessionEndReason})
	}
	return eps
}

// writeTestText prints a compact, grouped report. Divergences lead because they
// are the whole point: a protected endpoint a request defeated.
func writeTestText(out io.Writer, baseURL, project string, results []runtime.Result) {
	counts := map[runtime.Outcome]int{}
	for _, r := range results {
		counts[r.Outcome]++
	}

	fmt.Fprintf(out, "Runtime verification — %s against %s\n", project, baseURL)
	fmt.Fprintf(out, "  %d scenarios · %d pass · %d divergent · %d fail · %d blocked · %d unverified\n\n",
		len(results),
		counts[runtime.OutcomePass], counts[runtime.OutcomeDivergent],
		counts[runtime.OutcomeFail], counts[runtime.OutcomeBlocked], counts[runtime.OutcomeUnverified])

	// Divergent and fail first — the actionable results — then the rest.
	order := []runtime.Outcome{
		runtime.OutcomeDivergent, runtime.OutcomeFail, runtime.OutcomePass,
		runtime.OutcomeBlocked, runtime.OutcomeUnverified,
	}
	label := map[runtime.Outcome]string{
		runtime.OutcomeDivergent:  "DIVERGENT (static protected, runtime reachable)",
		runtime.OutcomeFail:       "FAIL (predicted reachable, denied)",
		runtime.OutcomePass:       "PASS",
		runtime.OutcomeBlocked:    "BLOCKED (safety: not executed)",
		runtime.OutcomeUnverified: "UNVERIFIED (could not conclude — not a pass)",
	}
	for _, oc := range order {
		group := make([]runtime.Result, 0)
		for _, r := range results {
			if r.Outcome == oc {
				group = append(group, r)
			}
		}
		if len(group) == 0 {
			continue
		}
		sort.Slice(group, func(i, j int) bool {
			if group[i].Path != group[j].Path {
				return group[i].Path < group[j].Path
			}
			return group[i].Identity.Role < group[j].Identity.Role
		})
		fmt.Fprintf(out, "%s\n", label[oc])
		for _, r := range group {
			fmt.Fprintf(out, "  %-4s %-30s as %-12s — %s\n",
				r.Method, r.Path, r.Identity.Role, r.Detail)
		}
		fmt.Fprintln(out)
	}

	if counts[runtime.OutcomeDivergent] > 0 {
		fmt.Fprintln(out, "A divergent result is the highest-confidence finding PathWise can make:")
		fmt.Fprintln(out, "the analysis said the endpoint was protected and the running app served it anyway.")
	}
}
