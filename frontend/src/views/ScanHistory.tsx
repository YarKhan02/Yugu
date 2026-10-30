import { useEffect, useMemo, useState } from "react";
import {
  ChevronRight, ChevronDown, ShieldAlert, Search, X, Copy, Share2, AlertTriangle,
} from "lucide-react";
import type { Scan, TestRun, RuntimeTest, RuntimeOutcome, Endpoint } from "../lib/types";
import type { View } from "../components/Sidebar";
import { MethodBadge, RoleTag } from "../components/primitives";
import { EndpointDetail } from "../components/Inspector";

// ScanHistory lists every runtime verification run recorded for the project,
// newest first — the durable, append-only record. Each run is kept separate and
// its results are never merged into the static findings. A row opens a detail
// drawer in place (not a navigation) so a result can be investigated alongside
// the scan's static evidence for the same endpoint.

// The five outcomes, with the plain-language meaning the UI must convey. A
// security product cannot let "fail" read as "confirmed vulnerability" or
// "unverified" read as "safe", so the wording here is deliberate.
const OUTCOME_META: Record<RuntimeOutcome, { label: string; cls: string; blurb: string }> = {
  divergent: { label: "Divergent", cls: "oc-divergent", blurb: "The runtime result contradicts the static baseline: the app served an endpoint the analysis proved was gated. The highest-confidence signal PathWise produces." },
  fail: { label: "Fail", cls: "oc-fail", blurb: "Observed behavior did not match the prediction. Inspect the exact mismatch — a mismatch is a disagreement to review, not yet a confirmed vulnerability." },
  pass: { label: "Pass", cls: "oc-pass", blurb: "Observed behavior matched the expected result." },
  blocked: { label: "Blocked", cls: "oc-blocked", blurb: "The scenario was not executed (for example a non-GET endpoint that was not opted in), so nothing was observed." },
  unverified: { label: "Unverified", cls: "oc-unverified", blurb: "There was insufficient evidence to decide whether the expected behavior holds. This is not a pass." },
};
const ORDER: RuntimeOutcome[] = ["divergent", "fail", "pass", "blocked", "unverified"];

export function ScanHistory({ scan, go }: { scan: Scan; go: (v: View, endpoint?: string) => void }) {
  const [history, setHistory] = useState<TestRun[]>(scan.history ?? []);

  // The App caches /api/scan at page load, so re-fetch on mount to pick up runs
  // executed this session (the server keeps them durably in the store).
  useEffect(() => {
    let live = true;
    fetch("api/scan")
      .then((r) => (r.ok ? r.json() : null))
      .then((d: Scan | null) => { if (live && d?.history) setHistory(d.history); })
      .catch(() => { /* keep the cached history */ });
    return () => { live = false; };
  }, []);

  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<RuntimeOutcome | "">("");
  const [open, setOpen] = useState<Set<string>>(() => (history[0] ? new Set([runKey(history[0])]) : new Set()));
  const [detail, setDetail] = useState<{ t: RuntimeTest; ep?: Endpoint } | null>(null);

  // Endpoint evidence is keyed by "METHOD /path", the same key a runtime result
  // carries, so a result can be joined to its static analysis in O(1).
  const epIndex = useMemo(() => {
    const m = new Map<string, Endpoint>();
    for (const e of scan.endpoints) m.set(`${e.method.toUpperCase()} ${e.path}`, e);
    return m;
  }, [scan.endpoints]);

  const q = query.trim().toLowerCase();

  // Filter rows by status and free text; a run also matches on its commit, id or
  // time, in which case all its rows are kept (still subject to the status chip).
  const shownRuns = useMemo(() => {
    return history
      .map((run) => {
        const metaHit = !!q && `${run.revision ?? ""} ${run.scanId} ${run.executedAt}`.toLowerCase().includes(q);
        const rows = run.results
          .filter((t) =>
            (!status || t.outcome === status) &&
            (!q || metaHit || `${t.method} ${t.path} ${t.role} ${t.detail}`.toLowerCase().includes(q)),
          )
          .sort((a, b) => rank(b.outcome) - rank(a.outcome) || a.path.localeCompare(b.path) || a.role.localeCompare(b.role));
        return { run, rows };
      })
      .filter(({ rows }) => rows.length > 0);
  }, [history, q, status]);

  const latest = history[0];
  const latestCounts = countOf(latest?.results ?? []);
  const filtered = status || q;

  if (history.length === 0) {
    return (
      <div className="page">
        <div className="pagehead"><h1>Scan history</h1></div>
        <div className="panelcard"><div className="hist-empty">
          No runtime runs recorded yet. Run a verification on the Runtime Tests page — every run is saved
          here, kept separate across scans, and survives refreshes.
        </div></div>
      </div>
    );
  }

  const allOpen = shownRuns.length > 0 && shownRuns.every(({ run }) => open.has(runKey(run)));
  const toggleAll = () =>
    setOpen(allOpen ? new Set() : new Set(shownRuns.map(({ run }) => runKey(run))));

  return (
    <div className="page">
      <div className="pagehead">
        <h1>Scan history</h1>
        <p>Review past runtime runs, investigate access-control discrepancies, and inspect each result against the static analysis. Runs are immutable and never merged with the static findings.</p>
      </div>

      {/* Summary: run count plus the newest run's outcome mix. These are run
          outcomes, not a count of unique vulnerabilities. */}
      <div className="hist-summary">
        <Stat label="Total runs" value={history.length} />
        <Stat label="Failed" value={latestCounts.fail ?? 0} tone="fail" />
        <Stat label="Passed" value={latestCounts.pass ?? 0} tone="pass" />
        <Stat label="Unverified" value={latestCounts.unverified ?? 0} tone="unverified" />
      </div>
      <p className="hist-note">Failed / passed / unverified reflect the newest run. They are run outcomes to investigate, not a tally of confirmed vulnerabilities.</p>

      <div className="hist-controls">
        <div className="search hist-search">
          <Search size={13} />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search endpoint, role, detail, commit or run id…" />
          {query && <button className="iconbtn" onClick={() => setQuery("")} aria-label="Clear search"><X size={13} /></button>}
        </div>
        <button className="btn ghost" onClick={toggleAll} disabled={shownRuns.length === 0}>
          {allOpen ? "Collapse all" : "Expand all"}
        </button>
      </div>

      <div className="hist-filters" role="group" aria-label="Filter by outcome">
        <button className={`chipbtn ${!status ? "active" : ""}`} onClick={() => setStatus("")}>All results</button>
        {ORDER.map((o) => (
          <button
            key={o}
            className={`chipbtn ${status === o ? "active" : ""}`}
            title={OUTCOME_META[o].blurb}
            onClick={() => setStatus(status === o ? "" : o)}
          >
            {OUTCOME_META[o].label}
          </button>
        ))}
      </div>

      {shownRuns.length === 0 ? (
        <div className="panelcard"><div className="hist-empty">No results match the current filters.{filtered && <> <button className="linkbtn" onClick={() => { setQuery(""); setStatus(""); }}>Clear filters</button></>}</div></div>
      ) : (
        <div className="hist-list">
          {shownRuns.map(({ run, rows }) => (
            <RunCard
              key={runKey(run)}
              run={run}
              rows={rows}
              roles={scan.roles}
              epIndex={epIndex}
              open={open.has(runKey(run))}
              onToggle={() => setOpen((s) => toggle(s, runKey(run)))}
              onPick={(t) => setDetail({ t, ep: epIndex.get(t.endpoint) })}
            />
          ))}
        </div>
      )}

      {detail && (
        <ResultDrawer t={detail.t} ep={detail.ep} scan={scan} onClose={() => setDetail(null)} go={go} />
      )}
    </div>
  );
}

function RunCard({
  run, rows, roles, epIndex, open, onToggle, onPick,
}: {
  run: TestRun;
  rows: RuntimeTest[];
  roles: string[];
  epIndex: Map<string, Endpoint>;
  open: boolean;
  onToggle: () => void;
  onPick: (t: RuntimeTest) => void;
}) {
  const counts = countOf(run.results);
  const divergent = counts.divergent ?? 0;

  return (
    <div className="hist-run">
      <div className="hist-head" onClick={onToggle} role="button" aria-expanded={open}>
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        <span className="hist-time">{fmtTime(run.executedAt)}</span>
        {run.revision && <span className="hist-rev" title="git revision">{run.revision.slice(0, 10)}</span>}
        {divergent > 0 && <span className="hist-diverge"><ShieldAlert size={12} /> {divergent} divergent</span>}
        <span className="hist-badges">
          {ORDER.filter((o) => counts[o]).map((o) => (
            <span key={o} className={`badge ${OUTCOME_META[o].cls}`}>{counts[o]} {OUTCOME_META[o].label.toLowerCase()}</span>
          ))}
        </span>
        <span className="hist-total">{run.results.length}</span>
      </div>
      {open && (
        <div className="rt-tablewrap">
          <table className="rt-table">
            <thead>
              <tr>
                <th>Method</th><th>Endpoint</th><th>Identity</th><th>Predicted</th><th>Response</th><th>Static</th><th>Outcome</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((t, i) => {
                const fcount = epIndex.get(t.endpoint)?.findings.length ?? 0;
                return (
                  <tr key={`${t.endpoint}|${t.role}|${i}`} className="rt-trow" onClick={() => onPick(t)} tabIndex={0}
                    onKeyDown={(e) => { if (e.key === "Enter") onPick(t); }}>
                    <td><MethodBadge method={t.method} /></td>
                    <td className="rt-ep mono">{t.path}</td>
                    <td><RoleTag role={t.role} roles={roles} /></td>
                    <td className="rt-pred">{t.expectation}</td>
                    <td className="rt-code mono">{t.status ? `HTTP ${t.status}` : "—"}</td>
                    <td className="rt-fcol">{fcount > 0 && <span className="rt-fwarn" title={`${fcount} static finding${fcount === 1 ? "" : "s"} on this endpoint`}><AlertTriangle size={11} /> {fcount}</span>}</td>
                    <td><span className={`badge ${OUTCOME_META[t.outcome].cls}`}>{OUTCOME_META[t.outcome].label}</span></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ResultDrawer explains one runtime result in place: what the scan predicted,
// what the app did, why they differ, and the static evidence for the endpoint
// (authorization path, roles & gates, data access, findings) so the prediction
// can be judged before calling a mismatch a vulnerability.
function ResultDrawer({
  t, ep, scan, onClose, go,
}: {
  t: RuntimeTest;
  ep?: Endpoint;
  scan: Scan;
  onClose: () => void;
  go: (v: View, endpoint?: string) => void;
}) {
  const expected = t.expectation === "allowed"
    ? "Reachable — the analysis found no gate that blocks this identity."
    : "Blocked — the analysis found a gate that should deny this identity.";
  const observed = t.status
    ? `The running app responded HTTP ${t.status}.`
    : "The scenario was not executed, so nothing was observed.";

  return (
    <div className="inspector-drawer">
      <div className="inspector">
        <div className="ihead">
          <div className="title">
            <MethodBadge method={t.method} />
            <span className="route mono">{t.path}</span>
            <button className="iconbtn close" onClick={onClose} aria-label="Close"><X size={14} /></button>
          </div>
          <div className="cellwrap" style={{ marginTop: 8 }}>
            <RoleTag role={t.role} roles={scan.roles} />
            <span className={`badge ${OUTCOME_META[t.outcome].cls}`}>{OUTCOME_META[t.outcome].label}</span>
          </div>
        </div>

        <section className="isec">
          <h3>Outcome</h3>
          <div className="kv"><span className="k">Expected</span><span className="v">{expected}</span></div>
          <div className="kv"><span className="k">Observed</span><span className="v">{observed}</span></div>
          <div className="kv"><span className="k">Why</span><span className="v">{t.detail}</span></div>
          <p className="rt-blurb">{OUTCOME_META[t.outcome].blurb}</p>
        </section>

        <section className="isec">
          <h3>Response data {t.body && <span style={{ color: "var(--muted)" }}>· capped 8 KB</span>}</h3>
          {t.body
            ? <pre className="rt-body">{prettyBody(t.body)}</pre>
            : <div style={{ color: "var(--muted)", fontSize: 12.5 }}>
                No response body was recorded for this result{t.status ? "" : " — the scenario was not executed"}.
              </div>}
        </section>

        <section className="isec">
          <h3>Actions</h3>
          <div className="cellwrap">
            <button className="btn" onClick={() => navigator.clipboard?.writeText(`${t.method} ${t.path}`)}><Copy size={13} /> Copy endpoint</button>
            <button className="btn" onClick={() => go("graph", t.endpoint)}><Share2 size={13} /> View in Access Graph</button>
          </div>
        </section>

        {ep ? (
          <EndpointDetail ep={ep} scan={scan} />
        ) : (
          <section className="isec">
            <h3>Static evidence</h3>
            <div style={{ color: "var(--muted)", fontSize: 12.5 }}>
              No static endpoint matched this route, so there is no analysis evidence to compare the runtime result against.
            </div>
          </section>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: "fail" | "pass" | "unverified" }) {
  return (
    <div className={`hist-stat ${tone ?? ""}`}>
      <div className="hist-stat-v">{value}</div>
      <div className="hist-stat-l">{label}</div>
    </div>
  );
}

function countOf(rows: RuntimeTest[]): Record<string, number> {
  const c: Record<string, number> = {};
  for (const r of rows) c[r.outcome] = (c[r.outcome] ?? 0) + 1;
  return c;
}
function rank(o: string): number {
  return ({ divergent: 4, fail: 3, pass: 2, blocked: 1, unverified: 0 } as Record<string, number>)[o] ?? 0;
}
function runKey(run: TestRun): string {
  return `${run.scanId}|${run.executedAt}`;
}
function toggle(s: Set<string>, k: string): Set<string> {
  const next = new Set(s);
  if (next.has(k)) next.delete(k); else next.add(k);
  return next;
}
function fmtTime(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}
// prettyBody indents JSON for readability; non-JSON (or truncated) bodies show
// verbatim.
function prettyBody(body: string): string {
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}
