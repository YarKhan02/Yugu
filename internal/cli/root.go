// Package cli defines the pathwise command tree.
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/YarKhan02/PathWise/internal/config"
	"github.com/YarKhan02/PathWise/internal/version"
)

// globalFlags are shared by every subcommand.
type globalFlags struct {
	projectDir string
	storePath  string
	verbose    bool
}

// resolveStorePath decides where PathWise's own SQLite database lives:
// the --store flag wins, then store in .pathwise.yaml, then the default. All
// commands share it so they read and write the same store.
func (g *globalFlags) resolveStorePath(projectRoot string) (string, error) {
	if g.storePath != "" {
		return storeFile(g.storePath), nil
	}
	cfg, err := config.Load(projectRoot)
	if err != nil {
		return "", err
	}
	if cfg.Store != "" {
		if filepath.IsAbs(cfg.Store) {
			return storeFile(cfg.Store), nil
		}
		return storeFile(filepath.Join(projectRoot, cfg.Store)), nil
	}
	return filepath.Join(projectRoot, ".pathwise", "pathwise.db"), nil
}

// storeFile treats a directory path (trailing slash, or an existing dir) as the
// store's home and places pathwise.db inside it; a file path is returned as is.
// SQLite handed a directory fails to open with a cryptic CANTOPEN, so resolve it.
func storeFile(p string) string {
	if strings.HasSuffix(p, string(os.PathSeparator)) {
		return filepath.Join(p, "pathwise.db")
	}
	if info, err := os.Stat(p); err == nil && info.IsDir() {
		return filepath.Join(p, "pathwise.db")
	}
	return p
}

// NewRootCommand builds the command tree.
func NewRootCommand() *cobra.Command {
	g := &globalFlags{}

	root := &cobra.Command{
		Use:   "pathwise",
		Short: "Trace execution and authorization paths through a Go application",
		Long: `PathWise reconstructs how an API request travels through a Go application,
determines which authorization checks actually affect it, and traces its
reachable PostgreSQL data — citing the source code or HTTP response that
proves each claim.

Where analysis cannot reach a conclusion it says so explicitly, naming what
defeated it. A silent pass is not a clean bill of health.`,
		Version:       version.Analyzer,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	pf := root.PersistentFlags()
	pf.StringVar(&g.projectDir, "project", ".", "path to the Go project to analyze")
	pf.StringVar(&g.storePath, "store", "", "path to PathWise's SQLite database (default <project>/.pathwise/pathwise.db)")
	pf.BoolVarP(&g.verbose, "verbose", "v", false, "verbose diagnostics")

	root.AddCommand(
		newScanCommand(g),
		newReportCommand(g),
		newServeCommand(g),
		newTestCommand(g),
		newDiffCommand(g),
	)
	return root
}

// notImplemented renders a consistent message for commands whose phase has
// not landed, rather than a stub that appears to succeed.
func notImplemented(cmd *cobra.Command, phase, what string) error {
	return fmt.Errorf("%s is not implemented yet (%s): %s", cmd.Name(), phase, what)
}
