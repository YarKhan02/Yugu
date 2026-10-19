package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/YarKhan02/PathWise/internal/model"
	"github.com/YarKhan02/PathWise/internal/project"
	"github.com/YarKhan02/PathWise/internal/report"
	"github.com/YarKhan02/PathWise/internal/storage/sqlite"
)

func newReportCommand(g *globalFlags) *cobra.Command {
	var out string

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Render the latest scan as a browsable role → endpoint → resource map",
		Long: `Report renders the most recent scan of the project into a single
self-contained HTML page: for each endpoint, the roles that gate it and the
database tables it reaches. It reads the stored scan, so it needs no
re-analysis and no database.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runReport(cmd.Context(), cmd, g, out)
		},
	}
	cmd.Flags().StringVar(&out, "out", "",
		"path to write the HTML report to (default <project>/.pathwise/report.html)")
	return cmd
}

func runReport(ctx context.Context, cmd *cobra.Command, g *globalFlags, out string) error {
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

	if out == "" {
		out = filepath.Join(filepath.Dir(storePath), "report.html")
	}
	rep, err := writeReport(ctx, store, scan, stored.Name, out)
	if err != nil {
		return err
	}

	o := cmd.OutOrStdout()
	fmt.Fprintf(o, "report written to %s\n", out)
	fmt.Fprintf(o, "  %d endpoints · %d roles · %d tables · %d findings · %d unresolved queries\n",
		rep.RouteCount, rep.RoleCount, rep.TableCount, rep.FindingCount, rep.UnresolvedCount)
	fmt.Fprintf(o, "  open it in a browser: open %s\n", out)
	return nil
}

// writeReport reads a scan's facts and findings, builds the report model, and
// writes the HTML to out. It is shared by the report command and by scan, which
// emits the report automatically so a scan is something you can see, not just a
// database on disk.
func writeReport(ctx context.Context, store *sqlite.Store, scan *sqlite.Scan, projectName, out string) (*report.Report, error) {
	rep, err := loadReport(ctx, store, scan, projectName)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return nil, fmt.Errorf("create report directory: %w", err)
	}
	f, err := os.Create(out)
	if err != nil {
		return nil, fmt.Errorf("create report: %w", err)
	}
	defer f.Close()
	if err := report.RenderHTML(f, rep); err != nil {
		return nil, fmt.Errorf("render report: %w", err)
	}
	return rep, nil
}

// loadReport reads a scan's facts and findings and builds the report model. It
// is shared by the report command, the scan command and the serve command, so
// all three present the same projection.
func loadReport(ctx context.Context, store *sqlite.Store, scan *sqlite.Scan, projectName string) (*report.Report, error) {
	routes, err := store.FactsByKind(ctx, scan.ID, model.FactRoute)
	if err != nil {
		return nil, err
	}
	middleware, err := store.FactsByKind(ctx, scan.ID, model.FactMiddleware)
	if err != nil {
		return nil, err
	}
	queries, err := store.FactsByKind(ctx, scan.ID, model.FactQuery)
	if err != nil {
		return nil, err
	}
	authChecks, err := store.FactsByKind(ctx, scan.ID, model.FactAuthCheckCandidate)
	if err != nil {
		return nil, err
	}
	tables, err := store.FactsByKind(ctx, scan.ID, model.FactTable)
	if err != nil {
		return nil, err
	}
	columns, err := store.FactsByKind(ctx, scan.ID, model.FactColumn)
	if err != nil {
		return nil, err
	}
	responses, err := store.FactsByKind(ctx, scan.ID, model.FactResponseField)
	if err != nil {
		return nil, err
	}
	foreignKeys, err := store.FactsByKind(ctx, scan.ID, model.FactForeignKey)
	if err != nil {
		return nil, err
	}
	findings, err := store.Findings(ctx, scan.ID)
	if err != nil {
		return nil, err
	}
	return report.Build(projectName, scan.ID, string(scan.SchemaSource),
		time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		routes, middleware, queries, authChecks, tables, columns, responses, foreignKeys, findings), nil
}
