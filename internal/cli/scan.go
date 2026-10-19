package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	ginadapter "github.com/YarKhan02/PathWise/internal/adapters/gin"
	"github.com/YarKhan02/PathWise/internal/analyzer"
	"github.com/YarKhan02/PathWise/internal/authorization"
	"github.com/YarKhan02/PathWise/internal/config"
	"github.com/YarKhan02/PathWise/internal/findings"
	"github.com/YarKhan02/PathWise/internal/loader"
	"github.com/YarKhan02/PathWise/internal/model"
	"github.com/YarKhan02/PathWise/internal/output"
	"github.com/YarKhan02/PathWise/internal/project"
	"github.com/YarKhan02/PathWise/internal/schema"
	"github.com/YarKhan02/PathWise/internal/storage/sqlite"
	"github.com/YarKhan02/PathWise/internal/version"
)

func newScanCommand(g *globalFlags) *cobra.Command {
	var (
		dbURL          string
		allowNoDB      bool
		migrationsFlag string
		format         string
		addr           string
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Analyze a project's routes, authorization logic and data access",
		Long: `Scan analyzes Go source and the PostgreSQL schema, then records an
immutable scan with the facts it established and the paths it could not
resolve.

The live database is authoritative for current schema. Without --db, scan
falls back to reconstructing schema from migrations and marks every schema
fact inferred rather than confirmed; pass --allow-no-db to accept that.

With --format json or sarif, scan prints the findings in that format to stdout
instead of the human summary, for piping into CI.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd.Context(), cmd, g, dbURL, allowNoDB, migrationsFlag, format, addr)
		},
	}

	f := cmd.Flags()
	f.StringVar(&dbURL, "db", "",
		"PostgreSQL connection URL, authoritative for current schema (overrides database_url in .pathwise.yaml; default $DATABASE_URL)")
	f.BoolVar(&allowNoDB, "allow-no-db", false,
		"proceed without a database, reconstructing schema from migrations only")
	f.StringVar(&migrationsFlag, "migrations", "",
		"directory of golang-migrate SQL files (overrides .pathwise.yaml)")
	f.StringVar(&format, "format", "text", "output format: text | json | sarif")
	f.StringVar(&addr, "addr", "127.0.0.1:7777",
		"listen address for the dashboard spun up after a text-format scan")

	return cmd
}

func runScan(ctx context.Context, cmd *cobra.Command, g *globalFlags,
	dbURL string, allowNoDB bool, migrationsFlag, format, addr string) error {

	out := cmd.OutOrStdout()

	proj, err := project.Resolve(g.projectDir)
	if err != nil {
		return err
	}

	cfg, err := config.Load(proj.Root)
	if err != nil {
		return err
	}
	if migrationsFlag != "" {
		cfg.MigrationsDir = migrationsFlag
	}

	// --db wins, then database_url in config, then $DATABASE_URL.
	if dbURL == "" {
		dbURL = cfg.DatabaseURL
	}
	if dbURL == "" {
		dbURL = os.Getenv("DATABASE_URL")
	}

	// Schema source is decided before any analysis runs, because it changes
	// the strength of every schema-derived conclusion downstream.
	schemaSource := sqlite.SchemaNone
	switch {
	case dbURL != "":
		schemaSource = sqlite.SchemaLive
	case cfg.MigrationsDir != "":
		if !allowNoDB {
			return fmt.Errorf(
				"no --db given: PathWise would reconstruct schema from %s and mark every schema fact inferred.\n"+
					"Pass --db \"$DATABASE_URL\" for authoritative schema, or --allow-no-db to accept inferred schema",
				cfg.MigrationsDir)
		}
		schemaSource = sqlite.SchemaMigrationsOnly
	default:
		if !allowNoDB {
			return fmt.Errorf(
				"no schema source: pass --db \"$DATABASE_URL\", set migrations_dir in %s, or pass --allow-no-db",
				config.FileName)
		}
	}

	storePath, err := g.resolveStorePath(proj.Root)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(storePath), 0o755); err != nil {
		return fmt.Errorf("create store directory: %w", err)
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

	disabled := cfg.DisabledFindings()

	scan, err := store.BeginScan(ctx, stored.ID, proj.GitRevision, proj.GitDirty,
		version.Analyzer, schemaSource, disabled)
	if err != nil {
		return err
	}

	// Schema first: its primary/unique keys are a premise of the ownership-check
	// (IDOR) finding, so it must be read before the authorization analysis.
	migrationsDir := cfg.MigrationsDir
	if migrationsDir != "" && !filepath.IsAbs(migrationsDir) {
		migrationsDir = filepath.Join(proj.Root, migrationsDir)
	}
	schemaFacts, keyCols, schemaSummary, schemaErr := readSchema(ctx, scan.ID, schemaSource, dbURL, migrationsDir)
	if schemaErr != nil {
		// The user asked for live schema with --db; a database that cannot be
		// read is a hard failure, not an empty-but-successful scan. Finish the
		// scan record so the failed attempt is preserved, then surface it.
		if err := store.FinishScan(ctx, scan.ID, schemaErr); err != nil {
			return err
		}
		return schemaErr
	}

	// Phases 1-3: route discovery, the endpoint → data-access map from the call
	// graph, and the authorization findings over each handler. Live schema keys
	// are confirmed; reconstructed ones are inferred, which weakens IDOR.
	ca := analyzeCode(scan.ID, proj.Root, cfg, keyCols, schemaSource == sqlite.SchemaLive)
	facts := append(ca.facts, schemaFacts...)

	written, insertErr := store.InsertFacts(ctx, facts)
	findingsWritten := 0
	if insertErr == nil {
		findingsWritten, insertErr = store.InsertFindings(ctx, ca.findings)
	}
	if err := store.FinishScan(ctx, scan.ID, insertErr); err != nil {
		return err
	}
	if insertErr != nil {
		return insertErr
	}

	// Machine formats print only the findings document, for piping into CI.
	if format != "text" {
		var data []byte
		var err error
		switch format {
		case "json":
			data, err = output.JSON(stored.Name, scan.ID, ca.findings)
		case "sarif":
			data, err = output.SARIF(stored.Name, scan.ID, ca.findings)
		default:
			return fmt.Errorf("unknown --format %q (want text, json or sarif)", format)
		}
		if err != nil {
			return err
		}
		fmt.Fprintln(out, string(data))
		return nil
	}

	fmt.Fprintf(out, "scan %s\n", scan.ID)
	fmt.Fprintf(out, "  project        %s (%s)\n", stored.Name, proj.ModulePath)
	fmt.Fprintf(out, "  revision       %s\n", describeRevision(proj))
	fmt.Fprintf(out, "  schema source  %s\n", schemaSource)
	fmt.Fprintf(out, "  facts recorded %d\n", written)
	fmt.Fprintf(out, "  routes         %s\n", ca.routeSummary)
	fmt.Fprintf(out, "  schema         %s\n", schemaSummary)
	fmt.Fprintf(out, "  data access    %s\n", ca.accessSummary)
	fmt.Fprintf(out, "  authorization  %s\n", ca.authSummary)
	fmt.Fprintf(out, "  findings       %d\n", findingsWritten)

	reportFindings(cmd, ca.findings)
	reportCoverage(cmd, cfg, disabled)

	// Emit the browsable report alongside the database, so a scan is something
	// you can open and read, not just a store on disk.
	reportPath := filepath.Join(filepath.Dir(storePath), "report.html")
	if _, err := writeReport(ctx, store, scan, stored.Name, reportPath); err != nil {
		fmt.Fprintf(out, "\n(could not write report: %v)\n", err)
	} else {
		fmt.Fprintf(out, "\nreport: %s  (open in a browser)\n", reportPath)
	}

	// Spin up the interactive dashboard so a scan is one command, not three.
	// It blocks until Ctrl-C; machine formats returned above, so CI is
	// unaffected. The signal context lets Ctrl-C shut the server down cleanly.
	// The scan has already succeeded and been persisted, so a dashboard that
	// cannot start (e.g. the port is taken) is reported but does not fail the
	// scan — the exit code must reflect the analysis, not the viewer.
	fmt.Fprintln(out)
	sctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serveDashboard(sctx, out, store, stored.ID, scan, stored.Name, addr); err != nil {
		fmt.Fprintf(out, "(dashboard not started: %v)\n"+
			"The scan succeeded — run `pathwise serve` to view it, or `pathwise report` for the static page.\n", err)
	}
	return nil
}

// reportFindings lists the authorization discrepancies the scan produced. A
// finding a developer cannot navigate to is a finding they will not fix, so
// each carries its endpoint and file:line.
func reportFindings(cmd *cobra.Command, findings []model.Finding) {
	if len(findings) == 0 {
		return
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "\n%d finding(s):\n", len(findings))
	for _, f := range findings {
		loc := ""
		if len(f.Locations) > 0 {
			loc = fmt.Sprintf(" (%s:%d)", f.Locations[0].File, f.Locations[0].StartLine)
		}
		fmt.Fprintf(out, "  [%s/%s] %s — %s%s\n", f.Severity, f.Confidence, f.Endpoint, f.Title, loc)
		fmt.Fprintf(out, "      %s\n", f.Detail)
	}
}

// readSchema reads the database schema for the scan and projects it to facts.
//
// Only the live path is implemented: it is the authoritative source the design
// is built around, and the migration-reconstruction fallback waits on the SQL
// parser that Phase 3 brings. Live schema is recorded as code_confirmed, the
// strongest evidence, so a finding resting on it reads as proven; a future
// migration-reconstructed schema will be inferred, so a finding resting on it
// reads as weaker. That difference is the point of tracking schema_source.
func readSchema(ctx context.Context, scanID string, src sqlite.SchemaSource, dbURL, migrationsDir string) (facts []model.Fact, keyCols map[string]map[string]bool, summary string, err error) {
	switch src {
	case sqlite.SchemaLive:
		sch, err := schema.ReadLive(ctx, dbURL)
		if err != nil {
			return nil, nil, "", fmt.Errorf("read live schema: %w", err)
		}
		ev := model.CodeConfirmed("live PostgreSQL information_schema",
			model.SourceLocation{File: "information_schema"})
		summary = fmt.Sprintf("%d tables, %d foreign keys (live)", len(sch.Tables), len(sch.ForeignKeys))
		return sch.Facts(scanID, ev), keyColumns(sch), summary, nil
	case sqlite.SchemaMigrationsOnly:
		sch, err := schema.Reconstruct(migrationsDir)
		if err != nil {
			return nil, nil, "", fmt.Errorf("reconstruct schema from migrations: %w", err)
		}
		ev := model.Inferred("schema reconstructed by replaying migrations in " + migrationsDir)
		summary = fmt.Sprintf("%d tables, %d foreign keys (reconstructed from migrations, inferred)", len(sch.Tables), len(sch.ForeignKeys))
		return sch.Facts(scanID, ev), keyColumns(sch), summary, nil
	default:
		return nil, nil, "not read (no schema source)", nil
	}
}

// keyColumns maps each table to the set of its primary- and single-column
// unique-key columns — the columns a request value must not reach unscoped. It
// is what makes missing_ownership_check active, so IDOR needs a live schema.
func keyColumns(sch *schema.Schema) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, t := range sch.Tables {
		set := map[string]bool{}
		for _, c := range t.PrimaryKey {
			set[c] = true
		}
		for _, u := range t.Unique {
			if len(u) == 1 {
				set[u[0]] = true
			}
		}
		if len(set) > 0 {
			out[t.Name] = set
		}
	}
	return out
}

// discoverRoutes runs the framework route adapters over the target and returns
// the facts they produced plus a one-line summary for the scan output.
//
// A load or build failure is not an empty result: go/packages (and therefore
// SSA) needs the target to compile, and a build that failed is the single most
// common reason a tool like this analyzes nothing. It is recorded as a
// build_error fact and surfaced in the summary so it can never be mistaken for
// "this application has no routes".
// codeAnalysis is everything the static passes produce from the loaded program.
type codeAnalysis struct {
	facts         []model.Fact
	findings      []model.Finding
	routeSummary  string
	accessSummary string
	authSummary   string
}

// analyzeCode runs the SSA-based passes over the target: route discovery
// (Phase 1), the endpoint → data-access map (Phase 2) and authorization-check
// enforcement (Phase 3).
//
// A load or build failure is not an empty result: go/packages (and therefore
// SSA) needs the target to compile, and a build that failed is the single most
// common reason a tool like this analyzes nothing. It is recorded as a
// build_error fact and surfaced in the summaries so it can never be mistaken
// for "this application has no routes".
func analyzeCode(scanID, root string, cfg *config.Config, keyCols map[string]map[string]bool, schemaConfirmed bool) codeAnalysis {
	loaded, err := loader.Load(root)
	if err != nil {
		return codeAnalysis{
			facts:         []model.Fact{buildErrorFact(scanID, model.SourceLocation{File: root}, err.Error())},
			routeSummary:  "not analyzed (load failed; recorded as build_error)",
			accessSummary: "not analyzed",
			authSummary:   "not analyzed",
		}
	}

	if errs := loaded.BuildErrors(); len(errs) > 0 {
		out := make([]model.Fact, 0, len(errs))
		for _, e := range errs {
			loc := model.SourceLocation{}
			if e.Pos != "" {
				loc.File = e.Pos
			}
			out = append(out, buildErrorFact(scanID, loc, e.Msg))
		}
		return codeAnalysis{
			facts:         out,
			routeSummary:  fmt.Sprintf("not analyzed (%d build error(s); recorded as build_error)", len(errs)),
			accessSummary: "not analyzed",
			authSummary:   "not analyzed",
		}
	}

	res := ginadapter.Discover(loaded.Prog, loaded.Packages)
	ca := codeAnalysis{facts: ginadapter.Facts(scanID, res)}
	ca.routeSummary = fmt.Sprintf("%d discovered", len(res.Routes))
	if len(res.Misses) > 0 {
		ca.routeSummary = fmt.Sprintf("%d discovered, %d unresolved", len(res.Routes), len(res.Misses))
	}

	embeds := analyzer.BuildEmbedIndex(loaded.Initial)
	cg := analyzer.BuildCallGraph(loaded.Prog)
	funcs := analyzer.FunctionsByName(loaded.Prog)

	access, _ := analyzeDataAccess(loaded.Prog, cg, funcs, res.Routes, embeds)
	accessFacts, accessSummary := dataAccessFacts(scanID, res.Routes, access)
	ca.facts = append(ca.facts, accessFacts...)
	ca.accessSummary = accessSummary

	authFacts, found, authSummary := analyzeFindings(scanID, loaded.Prog, cg, res.Routes, funcs, access, embeds, keyCols, schemaConfirmed, cfg)
	ca.facts = append(ca.facts, authFacts...)
	ca.findings = found
	ca.authSummary = authSummary

	return ca
}

// analyzeFindings is Phase 3: per route it runs the authorization findings over
// the handler's SSA and the data access reached from it. role_check_unenforced
// comes from SSA dominance over the handler's auth-check calls (and emits the
// auth_check_candidate/enforced facts that make the proof auditable);
// missing_tenant_filter and response_field_exceeds_scope come from the parsed
// queries and the serialized response, gated on the project's config.
func analyzeFindings(scanID string, prog *ssa.Program, cg *callgraph.Graph, routes []ginadapter.Route, funcs map[string]*ssa.Function, access map[string]analyzer.DBAccess, embeds analyzer.EmbedIndex, keyCols map[string]map[string]bool, schemaConfirmed bool, cfg *config.Config) (facts []model.Fact, found []model.Finding, summary string) {
	checkFuncs := map[string]bool{}
	for _, name := range cfg.AuthCheckFuncs {
		checkFuncs[name] = true
	}
	identityFuncs := map[string]bool{}
	for _, name := range cfg.IdentityFuncs {
		identityFuncs[name] = true
	}
	cls := analyzer.NewClassifier(cg, ginadapter.IsRequestSource, identityFuncs)

	examined := 0
	for _, r := range routes {
		ep := r.Subject()
		handler := funcs[r.Handler]
		acc := access[ep]

		if len(checkFuncs) > 0 && handler != nil {
			for _, chk := range authorization.CheckEnforcement(handler, checkFuncs, ginadapter.IsResponseWrite) {
				examined++
				subject := ep + " :: check " + chk.Func
				loc := model.SourceLocation{File: chk.Pos.Filename, StartLine: chk.Pos.Line, EndLine: chk.Pos.Line}
				facts = append(facts, model.Fact{
					ScanID:   scanID,
					Kind:     model.FactAuthCheckCandidate,
					Subject:  subject,
					Attrs:    map[string]any{"endpoint": ep, "check": chk.Func, "enforcement": string(chk.Enforcement)},
					Evidence: model.CodeConfirmed("authorization check call site", loc),
				})
				if chk.Enforcement.OK() {
					facts = append(facts, model.Fact{
						ScanID:   scanID,
						Kind:     model.FactAuthCheckEnforced,
						Subject:  subject,
						Attrs:    map[string]any{"endpoint": ep, "check": chk.Func},
						Evidence: model.CodeConfirmed("check failure branch dominates the response write", loc),
					})
					continue
				}
				found = append(found, roleCheckFinding(scanID, ep, chk, subject, loc))
			}
		}

		found = append(found, findings.TenantFilter(scanID, ep, acc.Queries, cfg)...)

		tablesRead := make([]string, 0, len(acc.Tables))
		for t := range acc.Tables {
			tablesRead = append(tablesRead, t)
		}
		found = append(found, findings.ResponseScope(scanID, ep, handler, tablesRead, cfg, ginadapter.ResponseBody)...)

		// Response fields the handler serializes — what the endpoint returns to
		// the client, recorded beside the tables it reads.
		if handler != nil {
			if rf := findings.ResponseFields(handler, ginadapter.ResponseBody); len(rf) > 0 {
				if pos := prog.Fset.Position(handler.Pos()); pos.Filename != "" {
					facts = append(facts, model.Fact{
						ScanID:   scanID,
						Kind:     model.FactResponseField,
						Subject:  ep + " :: response",
						Attrs:    map[string]any{"endpoint": ep, "fields": rf},
						Evidence: model.CodeConfirmed("serialized response struct fields", model.SourceLocation{File: pos.Filename, StartLine: pos.Line, EndLine: pos.Line}),
					})
				}
			}
		}

		// missing_ownership_check (IDOR): over the queries reachable from the
		// handler alone (not its auth middleware), gated to authenticated
		// endpoints, with the schema's keys and whether an ownership guard
		// dominates the response.
		if handler != nil && len(keyCols) > 0 {
			handlerAcc := analyzer.AnalyzeReachableDB(prog, cg, []*ssa.Function{handler}, embeds)
			authenticated := len(r.Middleware) > 0
			hasGuard := authorization.HasOwnershipGuard(handler, ginadapter.IsResponseWrite, cls.IsIdentity)
			found = append(found, findings.OwnershipCheck(scanID, ep, authenticated, hasGuard, handlerAcc.Queries, keyCols, cls, schemaConfirmed)...)
		}
	}

	summary = fmt.Sprintf("%d check(s) examined, %d finding(s)", examined, len(found))
	return facts, found, summary
}

// roleCheckFinding builds the finding for an authorization check that runs but
// does not gate the response. The confidence is proven: the verdict rests on
// SSA dominance, which is code_confirmed, not a heuristic.
func roleCheckFinding(scanID, endpoint string, chk authorization.Check, premise string, loc model.SourceLocation) model.Finding {
	var detail, remedy string
	switch chk.Enforcement {
	case authorization.Discarded:
		detail = fmt.Sprintf("The result of %s is discarded, so the check gates nothing while appearing to protect the endpoint.", chk.Func)
		remedy = "Branch on the check's result and abort the request when it fails, before any response body is written."
	case authorization.NonDominating:
		detail = fmt.Sprintf("%s is evaluated on only some paths to the response, so the response is reachable without the check having passed.", chk.Func)
		remedy = "Move the check so its failure aborts on every path that reaches the response write."
	default: // ResultNotGating
		detail = fmt.Sprintf("The result of %s never reaches a branch, so it cannot stop the request.", chk.Func)
		remedy = "Use the check's result to abort the request when it fails."
	}
	return model.Finding{
		ScanID:     scanID,
		Kind:       model.FindingRoleCheckUnenforced,
		Severity:   model.SeverityHigh,
		Confidence: model.ConfidenceProven,
		Endpoint:   endpoint,
		StableKey:  string(model.FindingRoleCheckUnenforced) + "|" + endpoint + "|" + chk.Func,
		Title:      "Authorization check not enforced: " + chk.Func,
		Detail:     detail,
		Remedy:     remedy,
		Locations:  []model.SourceLocation{loc},
		Premises:   []string{premise},
	}
}

// analyzeDataAccess is Phase 2: it builds the CHA→VTA call graph and, for each
// route, walks from the handler and its middleware to the database access they
// reach. It records one fact per (endpoint, table) with the operations seen,
// and a dynamic_sql fact for each endpoint that reaches a query built at
// runtime. The fact subject "ENDPOINT -> table" is the stable identity of that
// access edge.
func analyzeDataAccess(prog *ssa.Program, cg *callgraph.Graph, funcs map[string]*ssa.Function, routes []ginadapter.Route, embeds analyzer.EmbedIndex) (access map[string]analyzer.DBAccess, roots map[string][]*ssa.Function) {
	access = map[string]analyzer.DBAccess{}
	roots = map[string][]*ssa.Function{}
	for _, r := range routes {
		var rts []*ssa.Function
		for _, name := range append([]string{r.Handler}, r.MiddlewareNames()...) {
			if fn := funcs[name]; fn != nil {
				rts = append(rts, fn)
			}
		}
		roots[r.Subject()] = rts
		access[r.Subject()] = analyzer.AnalyzeReachableDB(prog, cg, rts, embeds)
	}
	return access, roots
}

// dataAccessFacts turns the per-route access into facts and a summary: one fact
// per (endpoint, table) with its operations, and a dynamic_sql fact for each
// endpoint that reaches a query built at runtime.
func dataAccessFacts(scanID string, routes []ginadapter.Route, access map[string]analyzer.DBAccess) (facts []model.Fact, summary string) {
	tablesTouched := map[string]bool{}
	dynamicEndpoints := 0
	for _, r := range routes {
		acc := access[r.Subject()]
		cols := analyzer.ColumnsByTable(acc)
		for table, ops := range acc.Tables {
			tablesTouched[table] = true
			attrs := map[string]any{"endpoint": r.Subject(), "table": table, "operations": ops}
			// Per-table field access, with the honest markers from attribution
			// (star = SELECT *, ambiguous = multi-table column it could not pin).
			if tc := cols[strings.ToLower(table)]; tc != nil {
				if len(tc.Read) > 0 {
					attrs["read_columns"] = tc.Read
				}
				if len(tc.Filter) > 0 {
					attrs["filter_columns"] = tc.Filter
				}
				if len(tc.Write) > 0 {
					attrs["write_columns"] = tc.Write
				}
				if tc.Star {
					attrs["columns_star"] = true
				}
				if tc.Ambiguous {
					attrs["columns_ambiguous"] = true
				}
			}
			facts = append(facts, model.Fact{
				ScanID:   scanID,
				Kind:     model.FactQuery,
				Subject:  r.Subject() + " -> " + table,
				Attrs:    attrs,
				Evidence: model.Inferred("table reached from the endpoint (pg_query_go parse)"),
			})
		}
		if len(acc.Unresolved) > 0 {
			dynamicEndpoints++
			u := acc.Unresolved[0]
			facts = append(facts, model.Fact{
				ScanID:  scanID,
				Kind:    model.FactQuery,
				Subject: r.Subject() + " -> (unresolved query)",
				Attrs:   map[string]any{"endpoint": r.Subject()},
				Evidence: model.Unresolved(u.Reason, u.Detail,
					model.SourceLocation{File: u.Pos.Filename, StartLine: u.Pos.Line, EndLine: u.Pos.Line}),
			})
		}
	}
	summary = fmt.Sprintf("%d endpoints, %d tables touched", len(routes), len(tablesTouched))
	if dynamicEndpoints > 0 {
		summary += fmt.Sprintf(", %d with unresolved queries", dynamicEndpoints)
	}
	return facts, summary
}

// buildErrorFact records that route discovery could not run because the target
// did not build. The detail carries the compiler message so the path to a fix
// is in the scan, not lost.
func buildErrorFact(scanID string, loc model.SourceLocation, detail string) model.Fact {
	return model.Fact{
		ScanID:   scanID,
		Kind:     model.FactRoute,
		Subject:  "route discovery unavailable",
		Evidence: model.Unresolved(model.ReasonBuildError, detail, loc),
	}
}

func describeRevision(p *project.Project) string {
	switch {
	case p.GitRevision == "":
		return "unknown (not a git repository; revision comparison unavailable)"
	case p.GitDirty:
		return p.GitRevision[:min(12, len(p.GitRevision))] + " (dirty: not comparable to other revisions)"
	default:
		return p.GitRevision[:min(12, len(p.GitRevision))]
	}
}

// reportCoverage states which checks could not run. A scan that finds nothing
// while two of four checks are inactive is a partial scan, and saying so is
// the difference between a trustworthy tool and a reassuring one.
func reportCoverage(cmd *cobra.Command, cfg *config.Config, disabled []model.FindingKind) {
	out := cmd.OutOrStdout()

	active := make([]model.FindingKind, 0, len(model.AllFindingKinds()))
	for _, k := range model.AllFindingKinds() {
		isDisabled := false
		for _, d := range disabled {
			if d == k {
				isDisabled = true
				break
			}
		}
		if !isDisabled {
			active = append(active, k)
		}
	}

	fmt.Fprintf(out, "\nchecks active (%d/%d):\n", len(active), len(model.AllFindingKinds()))
	for _, k := range active {
		fmt.Fprintf(out, "  + %s\n", k)
	}

	if len(disabled) == 0 {
		return
	}

	fmt.Fprintf(out, "checks inactive (%d) — these cannot report findings:\n", len(disabled))
	for _, k := range disabled {
		fmt.Fprintf(out, "  - %s: %s\n", k, reasonDisabled(k))
	}
	fmt.Fprintf(out, "\nConfigure %s to enable them. Absence of findings from an\n"+
		"inactive check is not evidence of absence of the problem.\n", config.FileName)
}

func reasonDisabled(k model.FindingKind) string {
	switch k {
	case model.FindingMissingTenantFilter:
		return "no tenancy.column declared, so no tenant discriminator is known"
	case model.FindingResponseFieldExceedsScope:
		return "no sensitive_columns declared, so no field has a scope to exceed"
	default:
		return "required configuration missing"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
