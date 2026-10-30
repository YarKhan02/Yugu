package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// TestResult is one planned scenario and its single execution, as the test
// command produces it. The split into test_scenarios (the intent) and test_runs
// (the observation) mirrors the schema. Runtime records are append-only, like
// facts and findings: a re-test writes new rows rather than editing old ones, so
// the history of what was observed when stays intact — and a runtime observation
// is never merged into the static conclusion it is tested against. The two kinds
// of evidence are stored apart so a contradiction between them stays visible.
type TestResult struct {
	Method       string // GET, POST, …
	Path         string // the route pattern, e.g. /students/{id}
	IdentityRole string // the role label the request was sent as
	Expectation  string // "allowed" | "blocked" — the static prediction
	SafetyClass  string // "allow" | "deny" — whether execution was permitted
	Outcome      string // pass | fail | blocked | unverified | divergent
	StatusCode   int    // 0 when the scenario was not executed
	Detail       string // the human-readable reason for the outcome
	// Body is a capped (8 KiB) preview of the response the app returned — the
	// data a real caller would see. It is the app's own output, not a credential;
	// request tokens are never captured here. Stored in test_runs.response_meta.
	Body string
}

// Endpoint is the stable METHOD /path identity used as the scenario key.
func (r TestResult) Endpoint() string { return r.Method + " " + r.Path }

// StoredTestResult is a TestResult read back, with the scan it tested and the
// time the run happened.
type StoredTestResult struct {
	TestResult
	ScanID     string
	ExecutedAt string
}

// InsertTestResults records one test run as a batch: a test_scenarios row (the
// plan) and a test_runs row (the observation) per result, in one transaction.
// Every row in the batch shares one executed_at, so "the latest run" is a single
// timestamp rather than a cluster of near-equal ones.
func (s *Store) InsertTestResults(ctx context.Context, scanID string, results []TestResult) (int, error) {
	if len(results) == 0 {
		return 0, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	insScenario, err := tx.PrepareContext(ctx,
		`INSERT INTO test_scenarios
		   (id, scan_id, endpoint, identity_ref, description, expectation, safety_class, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer insScenario.Close()

	insRun, err := tx.PrepareContext(ctx,
		`INSERT INTO test_runs
		   (id, scenario_id, request, status_code, response_meta, outcome, limitation, error, executed_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer insRun.Close()

	now := nowRFC3339()
	written := 0
	for _, r := range results {
		scenarioID := newID("scn")
		if _, err := insScenario.ExecContext(ctx,
			scenarioID, scanID, r.Endpoint(), r.IdentityRole, r.Detail,
			r.Expectation, r.SafetyClass, now); err != nil {
			return written, fmt.Errorf("insert scenario %s: %w", r.Endpoint(), err)
		}

		request, err := json.Marshal(map[string]string{"method": r.Method, "path": r.Path})
		if err != nil {
			return written, err
		}
		var status any // NULL when the scenario was not executed
		if r.StatusCode > 0 {
			status = r.StatusCode
		}
		meta := "{}"
		if r.Body != "" {
			if b, err := json.Marshal(map[string]string{"body": r.Body}); err == nil {
				meta = string(b)
			}
		}
		if _, err := insRun.ExecContext(ctx,
			newID("run"), scenarioID, string(request), status, meta,
			r.Outcome, r.Detail, "", now); err != nil {
			return written, fmt.Errorf("insert run %s: %w", r.Endpoint(), err)
		}
		written++
	}

	if err := tx.Commit(); err != nil {
		return written, err
	}
	return written, nil
}

// LatestTestResults returns the most recent test run for a scan — the batch with
// the greatest executed_at — or nil if the scan was never tested. The dashboard
// and `test --format` read this to show the current runtime picture rather than
// every historical attempt.
func (s *Store) LatestTestResults(ctx context.Context, scanID string) ([]StoredTestResult, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ts.endpoint, ts.identity_ref, ts.expectation, ts.safety_class,
		        tr.status_code, tr.outcome, tr.limitation, tr.executed_at, tr.response_meta
		 FROM test_runs tr
		 JOIN test_scenarios ts ON tr.scenario_id = ts.id
		 WHERE ts.scan_id = ?
		   AND tr.executed_at = (
		       SELECT MAX(tr2.executed_at) FROM test_runs tr2
		       JOIN test_scenarios ts2 ON tr2.scenario_id = ts2.id
		       WHERE ts2.scan_id = ?)
		 ORDER BY ts.endpoint, ts.identity_ref`,
		scanID, scanID)
	if err != nil {
		return nil, fmt.Errorf("query test results: %w", err)
	}
	defer rows.Close()

	var out []StoredTestResult
	for rows.Next() {
		var (
			r              StoredTestResult
			endpoint, meta string
			status         sql.NullInt64
		)
		if err := rows.Scan(&endpoint, &r.IdentityRole, &r.Expectation, &r.SafetyClass,
			&status, &r.Outcome, &r.Detail, &r.ExecutedAt, &meta); err != nil {
			return nil, err
		}
		r.ScanID = scanID
		r.Method, r.Path = splitEndpoint(endpoint)
		r.Body = bodyFromMeta(meta)
		if status.Valid {
			r.StatusCode = int(status.Int64)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// StoredRun is one recorded runtime run (a batch sharing an executed_at) with
// its results and the scan it tested — the unit of the dashboard's run history.
type StoredRun struct {
	ScanID      string
	ExecutedAt  string
	GitRevision string
	Results     []StoredTestResult
}

// AllTestRuns returns every runtime run recorded for a project, newest first,
// each grouped into its batch. Runs are append-only, so this is the full history
// across every scan of the checkout — a re-scan never drops earlier runs. The
// capped response-body preview is included so a result can be investigated.
func (s *Store) AllTestRuns(ctx context.Context, projectID string) ([]StoredRun, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ts.scan_id, tr.executed_at, sc.git_revision,
		        ts.endpoint, ts.identity_ref, ts.expectation, ts.safety_class,
		        tr.status_code, tr.outcome, tr.limitation, tr.response_meta
		 FROM test_runs tr
		 JOIN test_scenarios ts ON tr.scenario_id = ts.id
		 JOIN scans sc ON ts.scan_id = sc.id
		 WHERE sc.project_id = ?
		 ORDER BY tr.executed_at DESC, ts.endpoint, ts.identity_ref`,
		projectID)
	if err != nil {
		return nil, fmt.Errorf("query run history: %w", err)
	}
	defer rows.Close()

	var out []StoredRun
	for rows.Next() {
		var (
			scanID, executedAt, rev, endpoint, meta string
			r                                       StoredTestResult
			status                                  sql.NullInt64
		)
		if err := rows.Scan(&scanID, &executedAt, &rev, &endpoint, &r.IdentityRole,
			&r.Expectation, &r.SafetyClass, &status, &r.Outcome, &r.Detail, &meta); err != nil {
			return nil, err
		}
		r.ScanID = scanID
		r.ExecutedAt = executedAt
		r.Method, r.Path = splitEndpoint(endpoint)
		r.Body = bodyFromMeta(meta)
		if status.Valid {
			r.StatusCode = int(status.Int64)
		}
		// Rows are ordered by executed_at desc, so a new (scan, time) pair starts
		// a new batch.
		if n := len(out); n == 0 || out[n-1].ScanID != scanID || out[n-1].ExecutedAt != executedAt {
			out = append(out, StoredRun{ScanID: scanID, ExecutedAt: executedAt, GitRevision: rev})
		}
		out[len(out)-1].Results = append(out[len(out)-1].Results, r)
	}
	return out, rows.Err()
}

// bodyFromMeta reads the capped response-body preview out of a test_runs
// response_meta JSON blob, or "" when none was stored.
func bodyFromMeta(meta string) string {
	if meta == "" || meta == "{}" {
		return ""
	}
	var m struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal([]byte(meta), &m); err != nil {
		return ""
	}
	return m.Body
}

// splitEndpoint reverses TestResult.Endpoint ("METHOD /path").
func splitEndpoint(ep string) (method, path string) {
	for i := 0; i < len(ep); i++ {
		if ep[i] == ' ' {
			return ep[:i], ep[i+1:]
		}
	}
	return ep, ""
}
