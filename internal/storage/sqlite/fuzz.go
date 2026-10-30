package sqlite

import (
	"context"
	"fmt"
)

// FuzzBreak is one behavioral break the active fuzzer observed: a payload fired
// at an endpoint and the inconsistency it exposed. It is a runtime observation,
// stored apart from static findings so the two evidence kinds never merge.
type FuzzBreak struct {
	Endpoint string // "METHOD /path"
	Kind     string // the break kind, e.g. "write_read_inconsistency"
	Payload  string // the payload label that triggered it
	Detail   string // redacted, human-readable reason; never a raw response body
}

// StoredFuzzBreak is a FuzzBreak read back, with the scan it tested and when the
// run happened.
type StoredFuzzBreak struct {
	FuzzBreak
	ScanID     string
	ExecutedAt string
}

// InsertFuzzResults records one fuzz run's breaks as a batch sharing one
// executed_at, so "the latest run" is a single timestamp. An empty batch writes
// nothing: a clean run leaves no break rows.
func (s *Store) InsertFuzzResults(ctx context.Context, scanID string, breaks []FuzzBreak) (int, error) {
	if len(breaks) == 0 {
		return 0, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	ins, err := tx.PrepareContext(ctx,
		`INSERT INTO fuzz_results (id, scan_id, endpoint, break_kind, payload, detail, executed_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer ins.Close()

	now := nowRFC3339()
	written := 0
	for _, b := range breaks {
		if _, err := ins.ExecContext(ctx, newID("fzb"), scanID, b.Endpoint, b.Kind, b.Payload, b.Detail, now); err != nil {
			return written, fmt.Errorf("insert fuzz break %s %s: %w", b.Endpoint, b.Payload, err)
		}
		written++
	}

	if err := tx.Commit(); err != nil {
		return written, err
	}
	return written, nil
}

// LatestFuzzResults returns the breaks from the most recent fuzz run for a scan
// (the batch with the greatest executed_at), or nil if none was recorded. Note
// that nil means "no breaks" whether the scan was never fuzzed or the last run
// was clean; the caller knows which from the run it just issued.
func (s *Store) LatestFuzzResults(ctx context.Context, scanID string) ([]StoredFuzzBreak, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT endpoint, break_kind, payload, detail, executed_at
		 FROM fuzz_results
		 WHERE scan_id = ?
		   AND executed_at = (SELECT MAX(executed_at) FROM fuzz_results WHERE scan_id = ?)
		 ORDER BY endpoint, payload`,
		scanID, scanID)
	if err != nil {
		return nil, fmt.Errorf("query fuzz results: %w", err)
	}
	defer rows.Close()

	var out []StoredFuzzBreak
	for rows.Next() {
		r := StoredFuzzBreak{ScanID: scanID}
		if err := rows.Scan(&r.Endpoint, &r.Kind, &r.Payload, &r.Detail, &r.ExecutedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
