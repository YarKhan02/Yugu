-- Fuzz results record active mutation-testing observations: a payload fired at
-- an endpoint and the behavioral break it exposed. They are runtime
-- observations, kept apart from static findings and from auth-reachability test
-- runs, and are append-only like every other result (a re-run writes new rows).
-- No request tokens and no response bodies are stored: detail is a redacted,
-- human-readable reason, so a sensitive body a break revealed is never persisted.
CREATE TABLE fuzz_results (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES scans (id),
    endpoint    TEXT NOT NULL, -- "METHOD /path"
    break_kind  TEXT NOT NULL, -- endpoint_crash | write_read_inconsistency | write_not_persisted | validation_asymmetry
    payload     TEXT NOT NULL, -- the payload label, e.g. "missing:title"
    detail      TEXT NOT NULL,
    executed_at TEXT NOT NULL
);

CREATE INDEX idx_fuzz_results_scan ON fuzz_results (scan_id, executed_at);
