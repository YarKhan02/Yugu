# PathWise

**Prove who can reach which data through your Go web app — with evidence, not guesses.**

PathWise is a static-analysis CLI for Go web applications. For any endpoint and any identity, it answers one question:

> *Which database rows and response fields are reachable, and what in the source code (or in a live run) proves it?*

It does not match names or grep for `if role ==`. It uses the Go AST, type information, SSA, and control-flow analysis to **prove** that an authorization check actually gates a response — and it keeps every uncertainty visible instead of reporting a false all-clear.

---

## What it catches

Four finding types, each with a strict proof obligation:

| Finding | What it means |
|---|---|
| `missing_ownership_check` | A request-controlled value reaches a key lookup, and no identity-derived predicate or ownership guard constrains the response. |
| `role_check_unenforced` | A role/permission check exists but its result is ignored, or its failure branch doesn't actually block the response. |
| `missing_tenant_filter` | A query touches a tenant-scoped table without filtering on the tenant column. *(needs config)* |
| `response_field_exceeds_scope` | A response serializes a sensitive field outside the endpoint's allowed scope. *(needs config)* |

A *candidate* check is never treated as proof. PathWise verifies that failure handling **dominates** every relevant response path before it calls a check "enforced."

---

## How it works

PathWise has three cooperating modules built on **one shared data model** (`internal/model`). The model depends on nothing else; everything else produces or consumes its facts. This keeps the pieces honest: the dashboard and the runtime tester never parse Go source — they only read facts.

### The pipeline

```
Go source + migrations + live DB
        │
        ▼
┌─────────────────────────────────────────────┐
│ 1. STATIC ANALYSIS                            │
│    • load packages / SSA                      │
│    • build schema (live PostgreSQL, or        │
│      inferred from migrations)                │
│    • discover routes & middleware (Gin)       │
│    • build CHA → VTA call graph               │
│    • trace auth, request/identity provenance, │
│      SQL predicates, response construction    │
└───────────────┬───────────────────────────────┘
                │ emits structured FACTS + EVIDENCE
                ▼
┌─────────────────────────────────────────────┐
│ 2. RUNTIME VERIFICATION (optional)            │
│    • plan scenarios from the facts            │
│    • exercise the running app as supplied     │
│      identities (GET by default)              │
│    • compare observed behavior vs. prediction │
│      → pass / fail / divergent / blocked      │
└───────────────┬───────────────────────────────┘
                │ runtime results stored SEPARATELY
                ▼
┌─────────────────────────────────────────────┐
│ 3. STORAGE & PRESENTATION                     │
│    • SQLite store (immutable scans)           │
│    • dashboard, HTML report, access graph     │
└─────────────────────────────────────────────┘
```

### Evidence is typed, not scored

Every fact carries an evidence status — these are **different kinds of evidence**, not a confidence ladder:

- **`code_confirmed`** — proven by source/type/control-flow. Requires a source location.
- **`runtime_observed`** — seen in a specific scenario. Requires a scenario ID.
- **`inferred`** — heuristic. Must state the heuristic.
- **`unverified`** — analysis couldn't conclude. Requires a reason.

Static evidence and runtime observations are stored separately, and contradictions between them stay visible. Unknown is never rendered as safe.

---

## Install & build

```bash
go mod tidy
make corpus-tidy
make build        # produces ./pathwise
make ui           # rebuild embedded dashboard assets (needs Node)
make check        # vet + test
```

## Usage

### Scan (authoritative: live PostgreSQL schema)
```bash
./pathwise scan --project . --db "$DATABASE_URL"
./pathwise scan --project . --db "$DATABASE_URL" --format sarif
```

### Scan without a DB (degraded: schema inferred from migrations)
```bash
./pathwise scan --project . --allow-no-db
```
A scan with checks disabled or no DB is **partial**, not an all-clear — and PathWise says so.

### Runtime verification
Uses developer-supplied tokens. GET only unless you opt in per endpoint. Tokens are never stored.
```bash
./pathwise test --project . --base-url http://localhost:8080 \
  --identity student=<token> --identity admin=<token> \
  --allow "POST /batches" [--format json] [--no-store]
```

### View results
```bash
./pathwise report --project . [--out report.html]   # self-contained HTML report
./pathwise serve                                     # React dashboard (endpoints,
                                                     # DB, findings, inspector,
                                                     # access graph, runtime tests)
```

### Config (`.pathwise.yaml`)
Tenant and sensitive-field meaning are project policy and can't be inferred from schema alone. Without config, the two config-gated checks report as `inactive/unverified` with `missing_config` — never a silent pass. See `configs/pathwise.example.yaml`.

---

## Design principles

- **Proof over pattern-matching.** AST, types, SSA, control flow — never regex as evidence.
- **Preserve uncertainty.** Unresolved routes, dynamic SQL, reflection, interface dispatch, and build failures are reported explicitly, never skipped. A target that doesn't compile is a `build_error`, not "no findings."
- **Facts are the source of truth.** Graph nodes and edges are projections that can be rebuilt. Findings keep their premises so conclusions can be audited.
- **Scans are immutable.** Runtime results live separately from static findings.
- **No secrets persisted** — no DB credentials, no bearer tokens.

## Scope (V1)

Depth first: **Gin** routing, **raw SQL** (pgx / `database/sql`), **live PostgreSQL** schema, and the four finding types above. PathWise's own storage is SQLite (`modernc.org/sqlite`); SQL is parsed with `pg_query_go/v6`.

**Phase 7 (in progress):** more framework adapters, GORM support, scan-to-scan git diff, and CI mode.

## Repository map

| Path | Role |
|---|---|
| `cmd/pathwise/`, `internal/cli/` | CLI entry point and Cobra commands |
| `internal/model/` | shared facts, evidence, graph, findings (depends on nothing internal) |
| `internal/loader/`, `internal/project/` | Go package / SSA loading, project resolution |
| `internal/adapters/gin/` | Gin route & middleware discovery |
| `internal/schema/` | live PostgreSQL schema + migration reconstruction |
| `internal/analyzer/` | CHA→VTA call graph, endpoint→DB reachability |
| `internal/authorization/` | enforcement proofs |
| `internal/dataflow/` | SQL parsing, predicate provenance |
| `internal/findings/` | the four finding rules |
| `internal/runtime/` | scenario planning + HTTP verification |
| `internal/output/`, `internal/report/` | JSON/SARIF output, standalone HTML report |
| `internal/server/`, `frontend/` | API + embedded React/TypeScript dashboard |
| `internal/storage/sqlite/` | immutable scan storage |
| `internal/corpus/`, `testdata/apps/` | known-answer test corpus |
