// Mirrors the Go /api/scan contract in internal/server/scan.go. The frontend
// renders these conclusions; it never derives authorization itself.

export interface Location {
  file: string;
  start_line: number;
  end_line: number;
}

export interface Finding {
  id: string;
  kind: string;
  severity: "high" | "medium" | "low" | "info";
  confidence: "proven" | "likely" | "possible";
  endpoint: string;
  title: string;
  detail: string;
  remedy?: string;
  locations?: Location[];
  premises?: string[];
}

export interface Middleware {
  name: string;
  args?: string[];
}

export type Enforcement = "enforced" | "discarded" | "non_dominating" | "result_not_gating";

export interface Check {
  func: string;
  enforcement: Enforcement;
  enforced: boolean;
  file?: string;
  line?: number;
}

export interface TableRef {
  table: string;
  operations: string[];
  readColumns: string[];
  filterColumns: string[];
  writeColumns: string[];
  star: boolean;
  ambiguous: boolean;
}

export interface Endpoint {
  id: string;
  method: string;
  path: string;
  handler: string;
  handlerFile?: string;
  handlerLine?: number;
  roles: string[];
  middleware: Middleware[];
  checks: Check[];
  tables: TableRef[];
  responseFields: string[];
  unresolved: boolean;
  findings: Finding[];
  // Why this endpoint ends the caller's session (a logout and the like). When
  // set, it is left unticked by default so a test run does not log the token out.
  sessionEndReason?: string;
}

export interface ColumnInfo {
  name: string;
  type: string;
  nullable: boolean;
  primaryKey: boolean;
  foreignKey?: string;
}

export interface TableInfo {
  name: string;
  endpoints: string[];
  operations: string[];
  columns: ColumnInfo[];
}

export interface Counts {
  endpoints: number;
  roles: number;
  tables: number;
  findings: number;
  unresolved: number;
  severity: Record<string, number>;
}

export type RuntimeOutcome = "pass" | "fail" | "blocked" | "unverified" | "divergent";

export interface RuntimeTest {
  method: string;
  path: string;
  endpoint: string;
  role: string;
  expectation: "allowed" | "blocked";
  outcome: RuntimeOutcome;
  status?: number;
  detail: string;
  body?: string;
}

// FuzzFinding mirrors the /api/fuzz response (server.FuzzFinding): one
// behavioral break the active fuzzer observed. It carries no response body.
export interface FuzzFinding {
  endpoint: string;
  kind: string;
  payload: string;
  detail: string;
}

export interface TestRun {
  scanId: string;
  executedAt: string;
  revision?: string;
  results: RuntimeTest[];
}

export interface Scan {
  project: string;
  scanId: string;
  schemaSource: string;
  generatedAt: string;
  counts: Counts;
  roles: string[];
  tables: TableInfo[];
  endpoints: Endpoint[];
  findings: Finding[];
  runtimeTests: RuntimeTest[];
  runtimeTestedAt?: string;
  history: TestRun[];
}
