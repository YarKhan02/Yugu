package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/YarKhan02/PathWise/internal/project"
	"github.com/YarKhan02/PathWise/internal/report"
	"github.com/YarKhan02/PathWise/internal/runtime"
	"github.com/YarKhan02/PathWise/internal/server"
	"github.com/YarKhan02/PathWise/internal/storage/sqlite"
)

func newServeCommand(g *globalFlags) *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the interactive authorization-graph dashboard on localhost",
		Long: `Serve hosts an interactive dashboard for the latest scan: API endpoints on
one side, database tables on the other, with the edges between them. Select an
endpoint to trace the tables it reads, or a table to see which endpoints reach
it, and filter by the role each endpoint demands.

It reads the stored scan — run ` + "`pathwise scan`" + ` first — and serves a
self-contained page embedded in the binary, so there is nothing to build and no
network dependency.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd, g, addr)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:7777", "listen address for the dashboard")
	return cmd
}

func runServe(cmd *cobra.Command, g *globalFlags, addr string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	return serveDashboard(ctx, cmd.OutOrStdout(), store, stored.ID, scan, stored.Name, addr)
}

// serveDashboard loads the scan's projection and hosts the dashboard until ctx
// is cancelled. It is shared by `serve` and by `scan` (which spins it up as its
// final step), so both present the same page and the same in-dashboard runtime
// test runner. The runner keeps token handling in the CLI; the server never
// imports storage or runtime.
func serveDashboard(ctx context.Context, out io.Writer, store *sqlite.Store, projectID string, scan *sqlite.Scan, projectName, addr string) error {
	rep, err := loadReport(ctx, store, scan, projectName)
	if err != nil {
		return err
	}
	data := server.BuildScan(rep)

	// historyFn reads every recorded runtime run for the project from the store,
	// newest first — the durable history the dashboard shows and re-reads after
	// each new run. It spans all scans of the checkout, so a re-scan never drops
	// earlier runs.
	historyFn := func(ctx context.Context) ([]server.TestRun, error) {
		stored, err := store.AllTestRuns(ctx, projectID)
		if err != nil {
			return nil, err
		}
		out := make([]server.TestRun, 0, len(stored))
		for _, run := range stored {
			tr := server.TestRun{ScanID: run.ScanID, ExecutedAt: run.ExecutedAt, Revision: run.GitRevision}
			for _, r := range run.Results {
				tr.Results = append(tr.Results, server.RuntimeTest{
					Method: r.Method, Path: r.Path, Endpoint: r.Endpoint(), Role: r.IdentityRole,
					Expectation: r.Expectation, Outcome: r.Outcome, Status: r.StatusCode, Detail: r.Detail,
				})
			}
			out = append(out, tr)
		}
		return out, nil
	}

	// Seed the history and the current (latest) run from the store.
	if hist, err := historyFn(ctx); err != nil {
		return err
	} else if len(hist) > 0 {
		data.History = hist
		data.RuntimeTests = hist[0].Results
		data.RuntimeTestedAt = hist[0].ExecutedAt
	}

	runner := runtimeRunner(store, scan, rep)

	return server.Serve(ctx, addr, data, runner, historyFn, func(url string) {
		fmt.Fprintf(out, "PathWise dashboard — %s\n", projectName)
		fmt.Fprintf(out, "  %d endpoints · %d roles · %d tables · %d findings\n",
			data.Counts.Endpoints, data.Counts.Roles, data.Counts.Tables, data.Counts.Findings)
		fmt.Fprintf(out, "  open %s  (Ctrl-C to stop)\n", url)
	})
}

// runtimeRunner builds the dashboard's runtime-test handler: it plans scenarios
// from the scan's endpoints, runs them as the supplied identities and persists
// the results against the scan. Tokens arrive in the request, are used in
// memory, and are never stored — same contract as `pathwise test`.
func runtimeRunner(store *sqlite.Store, scan *sqlite.Scan, rep *report.Report) server.TestRunner {
	return func(ctx context.Context, req server.TestRequest) ([]server.RuntimeTest, error) {
		if strings.TrimSpace(req.BaseURL) == "" {
			return nil, fmt.Errorf("base URL is required: point it at the running application")
		}
		ids := make([]runtime.Identity, 0, len(req.Identities))
		for _, i := range req.Identities {
			role, token := strings.TrimSpace(i.Role), strings.TrimSpace(i.Token)
			// An empty token is allowed: it tests the endpoint as an
			// unauthenticated caller, which surfaces missing-auth endpoints.
			if role == "" {
				continue
			}
			ids = append(ids, runtime.Identity{Role: role, Token: token})
		}
		if len(ids) == 0 {
			return nil, fmt.Errorf("at least one identity with a role is required (token may be empty for an unauthenticated run)")
		}
		// The request names exactly which endpoints to run. A selected non-GET
		// is its own opt-in, so it is passed to Plan as allowed; GET runs
		// regardless. Endpoints not selected are dropped before planning.
		selected := make(map[string]bool, len(req.Endpoints))
		for _, k := range req.Endpoints {
			selected[k] = true
		}
		var eps []runtime.Endpoint
		allowed := map[string]bool{}
		for _, e := range endpointsForRuntime(rep) {
			key := runtime.Key(e.Method, e.Path)
			if !selected[key] {
				continue
			}
			eps = append(eps, e)
			if !strings.EqualFold(e.Method, "GET") {
				allowed[key] = true
			}
		}
		if len(eps) == 0 {
			return nil, fmt.Errorf("no endpoints selected to run")
		}

		scenarios := runtime.Plan(eps, ids, allowed)
		results := runtime.Run(ctx, req.BaseURL, scenarios, nil)
		if _, err := store.InsertTestResults(ctx, scan.ID, toStoredResults(results)); err != nil {
			return nil, fmt.Errorf("record test results: %w", err)
		}
		return toRuntimeTests(results), nil
	}
}

// toRuntimeTests projects runtime results onto the dashboard contract.
func toRuntimeTests(results []runtime.Result) []server.RuntimeTest {
	out := make([]server.RuntimeTest, 0, len(results))
	for _, r := range results {
		expectation := "blocked"
		if r.ExpectAllowed {
			expectation = "allowed"
		}
		out = append(out, server.RuntimeTest{
			Method: r.Method, Path: r.Path, Endpoint: runtime.Key(r.Method, r.Path),
			Role: r.Identity.Role, Expectation: expectation, Outcome: string(r.Outcome),
			Status: r.Status, Detail: r.Detail, Body: r.Body,
		})
	}
	return out
}
