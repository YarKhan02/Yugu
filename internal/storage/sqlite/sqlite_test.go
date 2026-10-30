package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/YarKhan02/PathWise/internal/model"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()

	s, err := Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestMigrationsAreIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "idem.db")

	first, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	_ = first.Close()

	second, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen must not re-apply migrations: %v", err)
	}
	_ = second.Close()
}

func TestUpsertProjectIsStableByRoot(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	a, err := s.UpsertProject(ctx, "app", "/src/app", "example.com/app")
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	b, err := s.UpsertProject(ctx, "app", "/src/app", "example.com/app")
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	if a.ID != b.ID {
		t.Error("repeated scans of one checkout must share a project, not fork history")
	}
}

// TestScansAreImmutable asserts a new scan does not disturb an older one's
// facts. Historical evidence is what makes revision comparison possible.
func TestScansAreImmutable(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	proj, err := s.UpsertProject(ctx, "app", "/src/app", "example.com/app")
	if err != nil {
		t.Fatal(err)
	}

	first, err := s.BeginScan(ctx, proj.ID, "abc123", false, "0.1.0", SchemaLive, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.InsertFacts(ctx, []model.Fact{{
		ScanID:   first.ID,
		Kind:     model.FactRoute,
		Subject:  "GET /students/{id}",
		Evidence: model.CodeConfirmed("gin route", model.SourceLocation{File: "main.go", StartLine: 20, EndLine: 20}),
	}}); err != nil {
		t.Fatalf("insert into first scan: %v", err)
	}
	if err := s.FinishScan(ctx, first.ID, nil); err != nil {
		t.Fatal(err)
	}

	second, err := s.BeginScan(ctx, proj.ID, "def456", false, "0.1.0", SchemaLive, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertFacts(ctx, []model.Fact{{
		ScanID:   second.ID,
		Kind:     model.FactRoute,
		Subject:  "GET /batches",
		Evidence: model.CodeConfirmed("gin route", model.SourceLocation{File: "main.go", StartLine: 25, EndLine: 25}),
	}}); err != nil {
		t.Fatalf("insert into second scan: %v", err)
	}

	n, err := s.CountFacts(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("first scan has %d facts after a later scan, want 1", n)
	}

	latest, err := s.LatestScan(ctx, proj.ID)
	if err != nil {
		t.Fatal(err)
	}
	if latest.ID != second.ID {
		t.Error("LatestScan must return the newest scan; sortable IDs should make this an ORDER BY")
	}
}

func TestInsertFactsDeduplicates(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	proj, _ := s.UpsertProject(ctx, "app", "/src/app", "example.com/app")
	scan, _ := s.BeginScan(ctx, proj.ID, "abc", false, "0.1.0", SchemaLive, nil)

	fact := model.Fact{
		ScanID:   scan.ID,
		Kind:     model.FactRoute,
		Subject:  "GET /students/{id}",
		Attrs:    map[string]any{"handler": "main.GetStudent"},
		Evidence: model.CodeConfirmed("gin", model.SourceLocation{File: "main.go", StartLine: 1, EndLine: 1}),
	}

	written, err := s.InsertFacts(ctx, []model.Fact{fact, fact})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if written != 1 {
		t.Errorf("wrote %d facts for one duplicated fact, want 1", written)
	}
}

// TestInsertFactsRejectsMalformedEvidence is the guard that keeps the tool
// honest: an unverified fact with no stated reason is indistinguishable from
// a safe one to a reader, so storage refuses it outright.
func TestInsertFactsRejectsMalformedEvidence(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	proj, _ := s.UpsertProject(ctx, "app", "/src/app", "example.com/app")
	scan, _ := s.BeginScan(ctx, proj.ID, "abc", false, "0.1.0", SchemaLive, nil)

	_, err := s.InsertFacts(ctx, []model.Fact{{
		ScanID:   scan.ID,
		Kind:     model.FactQuery,
		Subject:  "main.SearchStudents",
		Evidence: model.Evidence{Status: model.StatusUnverified}, // no reason
	}})
	if err == nil {
		t.Fatal("expected storage to reject unverified evidence with no reason")
	}
}

func TestFactsRoundTripWithLocations(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	proj, _ := s.UpsertProject(ctx, "app", "/src/app", "example.com/app")
	scan, _ := s.BeginScan(ctx, proj.ID, "abc", false, "0.1.0", SchemaLive, nil)

	in := model.Fact{
		ScanID:  scan.ID,
		Kind:    model.FactQueryPredicate,
		Subject: "students.id",
		Attrs: map[string]any{
			"provenance": string(model.ProvenanceRequest),
			"operation":  string(model.OpSelect),
		},
		Evidence: model.CodeConfirmed("WHERE id = $1 bound from c.Param",
			model.SourceLocation{File: "store.go", StartLine: 44, EndLine: 47}),
	}

	if _, err := s.InsertFacts(ctx, []model.Fact{in}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	out, err := s.FactsByKind(ctx, scan.ID, model.FactQueryPredicate)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("read %d facts, want 1", len(out))
	}

	got := out[0]
	if got.Subject != in.Subject {
		t.Errorf("subject = %q, want %q", got.Subject, in.Subject)
	}
	if got.Attrs["provenance"] != string(model.ProvenanceRequest) {
		t.Errorf("provenance = %v, want %q", got.Attrs["provenance"], model.ProvenanceRequest)
	}
	if len(got.Evidence.Source) != 1 || got.Evidence.Source[0].StartLine != 44 {
		t.Errorf("source locations did not round trip: %+v", got.Evidence.Source)
	}
}

// TestTestResultsRoundTripAndLatest asserts runtime results persist and that
// LatestTestResults returns only the most recent run, so a re-test supersedes
// the previous picture without destroying its history.
func TestTestResultsRoundTripAndLatest(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	proj, _ := s.UpsertProject(ctx, "app", "/src/app", "example.com/app")
	scan, _ := s.BeginScan(ctx, proj.ID, "abc", false, "0.1.0", SchemaLive, nil)

	first := []TestResult{
		{Method: "GET", Path: "/admin/reports", IdentityRole: "student",
			Expectation: "blocked", SafetyClass: "allow", Outcome: "divergent", StatusCode: 200, Detail: "served to student"},
		{Method: "POST", Path: "/batches", IdentityRole: "admin",
			Expectation: "allowed", SafetyClass: "deny", Outcome: "blocked", Detail: "non-GET"},
	}
	if _, err := s.InsertTestResults(ctx, scan.ID, first); err != nil {
		t.Fatalf("insert first batch: %v", err)
	}

	// A later run with a single result must become the whole "latest" picture.
	second := []TestResult{
		{Method: "GET", Path: "/dashboard", IdentityRole: "admin",
			Expectation: "allowed", SafetyClass: "allow", Outcome: "pass", StatusCode: 200, Detail: "reachable",
			Body: `{"ok":true}`},
	}
	if _, err := s.InsertTestResults(ctx, scan.ID, second); err != nil {
		t.Fatalf("insert second batch: %v", err)
	}

	got, err := s.LatestTestResults(ctx, scan.ID)
	if err != nil {
		t.Fatalf("read latest: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("latest run should be the 1 newest result, got %d", len(got))
	}
	r := got[0]
	if r.Method != "GET" || r.Path != "/dashboard" || r.Outcome != "pass" || r.StatusCode != 200 {
		t.Errorf("latest result did not round trip: %+v", r)
	}
	if r.Body != `{"ok":true}` {
		t.Errorf("response body did not round trip: got %q", r.Body)
	}
	if r.ScanID != scan.ID {
		t.Errorf("scan id = %q, want %q", r.ScanID, scan.ID)
	}
}

func TestFuzzResultsRoundTripAndLatest(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	proj, _ := s.UpsertProject(ctx, "app", "/src/app", "example.com/app")
	scan, _ := s.BeginScan(ctx, proj.ID, "abc", false, "0.1.0", SchemaLive, nil)

	first := []FuzzBreak{
		{Endpoint: "POST /assignments", Kind: "write_read_inconsistency", Payload: "missing:title", Detail: "accepted, read failed"},
		{Endpoint: "POST /assignments", Kind: "endpoint_crash", Payload: "wrongType:count", Detail: "500 reproduced"},
	}
	if _, err := s.InsertFuzzResults(ctx, scan.ID, first); err != nil {
		t.Fatalf("insert first batch: %v", err)
	}

	// A later run becomes the whole "latest" picture, not merged with the first.
	second := []FuzzBreak{
		{Endpoint: "PATCH /lessons/{id}", Kind: "write_not_persisted", Payload: "baseline", Detail: "not reflected on read-back"},
	}
	if _, err := s.InsertFuzzResults(ctx, scan.ID, second); err != nil {
		t.Fatalf("insert second batch: %v", err)
	}

	got, err := s.LatestFuzzResults(ctx, scan.ID)
	if err != nil {
		t.Fatalf("read latest: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("latest run should be the 1 newest break, got %d", len(got))
	}
	b := got[0]
	if b.Endpoint != "PATCH /lessons/{id}" || b.Kind != "write_not_persisted" || b.Payload != "baseline" {
		t.Errorf("fuzz break did not round trip: %+v", b)
	}
	if b.ScanID != scan.ID || b.ExecutedAt == "" {
		t.Errorf("scan id / executed_at not set: %+v", b)
	}
}

// TestInsertFuzzResultsEmpty is the negative control: a clean run (no breaks)
// writes nothing and reads back as no breaks, never an error.
func TestInsertFuzzResultsEmpty(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	proj, _ := s.UpsertProject(ctx, "app", "/src/app", "example.com/app")
	scan, _ := s.BeginScan(ctx, proj.ID, "abc", false, "0.1.0", SchemaLive, nil)

	if n, err := s.InsertFuzzResults(ctx, scan.ID, nil); err != nil || n != 0 {
		t.Fatalf("empty insert = %d,%v, want 0,nil", n, err)
	}
	if got, err := s.LatestFuzzResults(ctx, scan.ID); err != nil || len(got) != 0 {
		t.Fatalf("latest after clean run = %v,%v, want empty", got, err)
	}
}

// TestAllTestRunsKeepsRunsSeparate is the negative control for the history list:
// two runs against the same scan must stay two separate records, newest first,
// never merged into one — the whole point of an append-only runtime history.
func TestAllTestRunsKeepsRunsSeparate(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	proj, _ := s.UpsertProject(ctx, "app", "/src/app", "example.com/app")
	scan, _ := s.BeginScan(ctx, proj.ID, "abc", false, "0.1.0", SchemaLive, nil)

	first := []TestResult{
		{Method: "GET", Path: "/a", IdentityRole: "student", Expectation: "blocked", SafetyClass: "allow", Outcome: "divergent", StatusCode: 200, Detail: "served"},
		{Method: "GET", Path: "/b", IdentityRole: "admin", Expectation: "allowed", SafetyClass: "allow", Outcome: "pass", StatusCode: 200, Detail: "ok"},
	}
	second := []TestResult{
		{Method: "GET", Path: "/c", IdentityRole: "admin", Expectation: "allowed", SafetyClass: "allow", Outcome: "pass", StatusCode: 200, Detail: "ok"},
	}
	if _, err := s.InsertTestResults(ctx, scan.ID, first); err != nil {
		t.Fatalf("insert first run: %v", err)
	}
	if _, err := s.InsertTestResults(ctx, scan.ID, second); err != nil {
		t.Fatalf("insert second run: %v", err)
	}

	runs, err := s.AllTestRuns(ctx, proj.ID)
	if err != nil {
		t.Fatalf("read run history: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("two inserts must yield two separate runs, got %d", len(runs))
	}
	// Newest first: the single-result run leads, the two-result run follows.
	if len(runs[0].Results) != 1 || len(runs[1].Results) != 2 {
		t.Errorf("runs merged or misordered: got sizes %d, %d (want 1, 2)", len(runs[0].Results), len(runs[1].Results))
	}
	if runs[0].ExecutedAt == runs[1].ExecutedAt {
		t.Errorf("distinct runs share an executed_at (%q): they would collapse into one", runs[0].ExecutedAt)
	}
}
