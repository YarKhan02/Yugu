import { useMemo, useState } from "react";
import { ShieldAlert, Check, ArrowRight, X, Play, Plus, Trash2, Search } from "lucide-react";
import type { Scan, RuntimeTest } from "../lib/types";
import type { View } from "../components/Sidebar";
import { runTests } from "../lib/api";

export function RuntimeTests({ scan, go }: { scan: Scan; go: (v: View, endpoint?: string) => void }) {
  // The full per-endpoint results live on the Scan History page, where every run
  // is kept as its own record. This page only runs a test and confirms it — the
  // long outcome list is deliberately not rendered here.
  const [last, setLast] = useState<{ total: number; divergent: number; fail: number } | null>(null);

  return (
    <div className="page">
      <div className="pagehead">
        <h1>Runtime verification</h1>
        <p>
          Exercise the running application as each identity and compare what it does with what the scan
          predicted. Every run is recorded separately in Scan History and never merged with the static findings.
        </p>
      </div>

      <RunForm scan={scan} onDone={(r) => setLast(summarize(r))} />

      {last && (
        <div className={`rt-banner ${last.divergent > 0 ? "" : "ok"}`}>
          <div className="ic">{last.divergent > 0 ? <ShieldAlert size={20} /> : <Check size={20} />}</div>
          <div>
            <h3>
              Run recorded — {last.total} scenario{last.total === 1 ? "" : "s"}
              {last.divergent > 0 ? `, ${last.divergent} divergent` : ""}
              {last.fail > 0 ? `, ${last.fail} failed` : ""}
            </h3>
            <p>
              {last.divergent > 0
                ? "The analysis said some endpoints were protected and the running app served them anyway. "
                : ""}
              See the full outcome of this and every earlier run on the Scan History page.
            </p>
            <button className="btn" style={{ marginTop: 8 }} onClick={() => go("history")}>
              Open Scan History <ArrowRight size={13} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// summarize reduces a run to the two counts worth flagging here; the per-endpoint
// detail is left to the Scan History page.
function summarize(r: RuntimeTest[]): { total: number; divergent: number; fail: number } {
  let divergent = 0;
  let fail = 0;
  for (const t of r) {
    if (t.outcome === "divergent") divergent++;
    else if (t.outcome === "fail") fail++;
  }
  return { total: r.length, divergent, fail };
}

// RunForm collects the base URL, an editable identity list (seeded from the
// scan's roles) and the per-endpoint opt-in for non-GET methods, then asks the
// server to run the test. Tokens are typed here and sent to localhost only.
function RunForm({ scan, onDone }: { scan: Scan; onDone: (r: RuntimeTest[]) => void }) {
  const [baseUrl, setBaseUrl] = useState("http://localhost:8080");
  const [ids, setIds] = useState<{ role: string; token: string; on: boolean }[]>(
    scan.roles.length
      ? [...scan.roles.map((role) => ({ role, token: "", on: false })), { role: "anonymous", token: "", on: false }]
      : [{ role: "", token: "", on: false }],
  );
  // Endpoints that end the caller's session (logout and the like), keyed
  // "METHOD /path". Testing one invalidates the token every other scenario runs
  // as, so they are never on by default — ticking one is an explicit opt-in.
  const sessionEnders = useMemo(() => {
    const s = new Set<string>();
    for (const e of scan.endpoints) {
      if (e.sessionEndReason) s.add(`${e.method.toUpperCase()} ${e.path}`);
    }
    return s;
  }, [scan.endpoints]);

  // The endpoints to run. GET is selected by default (read-only, safe) unless it
  // ends the session; non-GET and session-enders start off and are explicit
  // opt-ins, because they can mutate, delete data, or log the token out.
  const [allow, setAllow] = useState<Set<string>>(() => {
    const s = new Set<string>();
    for (const e of scan.endpoints) {
      const key = `GET ${e.path}`;
      if (e.method.toUpperCase() === "GET" && !e.sessionEndReason) s.add(key);
    }
    return s;
  });
  const [allowQuery, setAllowQuery] = useState("");
  const [methodFilter, setMethodFilter] = useState<Set<string>>(new Set());
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");

  // Every distinct endpoint, as "METHOD /path".
  const allEps = useMemo(() => {
    const seen = new Set<string>();
    for (const e of scan.endpoints) seen.add(`${e.method.toUpperCase()} ${e.path}`);
    return [...seen].sort();
  }, [scan.endpoints]);

  // The methods present, with a count each, for the filter chips.
  const methodCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const k of allEps) {
      const m = k.split(" ", 1)[0];
      c[m] = (c[m] ?? 0) + 1;
    }
    return c;
  }, [allEps]);
  const methods = useMemo(() => Object.keys(methodCounts).sort(), [methodCounts]);

  const shownEps = useMemo(() => {
    const q = allowQuery.trim().toLowerCase();
    return allEps.filter(
      (k) =>
        (methodFilter.size === 0 || methodFilter.has(k.split(" ", 1)[0])) &&
        (!q || k.toLowerCase().includes(q)),
    );
  }, [allEps, allowQuery, methodFilter]);

  const allShownSelected = shownEps.length > 0 && shownEps.every((k) => allow.has(k));
  const toggleAllShown = () =>
    setAllow((s) => {
      const next = new Set(s);
      if (allShownSelected) shownEps.forEach((k) => next.delete(k));
      else shownEps.forEach((k) => next.add(k));
      return next;
    });
  const toggleMethod = (m: string) =>
    setMethodFilter((s) => {
      const next = new Set(s);
      if (next.has(m)) next.delete(m);
      else next.add(m);
      return next;
    });

  const setId = (i: number, patch: Partial<{ role: string; token: string; on: boolean }>) =>
    setIds((xs) => xs.map((x, j) => (j === i ? { ...x, ...patch } : x)));

  const run = async () => {
    setError("");
    setRunning(true);
    try {
      // Only ticked identities with a role and token run; the role each is
      // predicted-allowed for is decided per endpoint by the scan's gates.
      // Token may be empty: an identity with no token runs unauthenticated,
      // to catch endpoints reachable without any credential.
      const identities = ids
        .filter((x) => x.on && x.role.trim())
        .map(({ role, token }) => ({ role, token }));
      const r = await runTests({ baseUrl: baseUrl.trim(), identities, endpoints: [...allow] });
      onDone(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="rt-form panelcard">
      <label className="rt-field">
        <span>Base URL</span>
        <input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="http://localhost:8080" />
      </label>

      <div className="rt-field">
        <span>Identities <em>(role matched against the scan's gates; token is a bearer credential, never stored — leave it empty to run unauthenticated)</em></span>
        {ids.map((id, i) => (
          <div key={i} className={`rt-idrow ${id.on ? "" : "off"}`}>
            <input type="checkbox" title="run as this identity" checked={id.on} onChange={(e) => setId(i, { on: e.target.checked })} />
            <input className="rt-role" value={id.role} placeholder="role" onChange={(e) => setId(i, { role: e.target.value })} />
            <input className="rt-token" type="password" value={id.token} placeholder="token (empty = unauthenticated)" onChange={(e) => setId(i, { token: e.target.value })} />
            <button className="btn ghost" title="remove" onClick={() => setIds((xs) => xs.filter((_, j) => j !== i))}><Trash2 size={13} /></button>
          </div>
        ))}
        <button className="btn ghost" style={{ alignSelf: "start" }} onClick={() => setIds((xs) => [...xs, { role: "", token: "", on: true }])}>
          <Plus size={13} /> Add identity
        </button>
      </div>

      {allEps.length > 0 && (
        <div className="rt-field">
          <span>Endpoints to run <em>(GET is on by default — read-only and safe; non-GET is off, ticking one opts it in and it can mutate or delete data in the running app)</em></span>
          <div className="rt-allowmethods">
            {methods.map((m) => (
              <button key={m} className={`rolebtn ${methodFilter.has(m) ? "active" : ""}`} onClick={() => toggleMethod(m)}>
                {m} <span className="rt-mcount">{methodCounts[m]}</span>
              </button>
            ))}
            {methodFilter.size > 0 && <button className="btn ghost" onClick={() => setMethodFilter(new Set())}>All methods</button>}
          </div>
          <div className="rt-allowhead">
            <div className="search">
              <Search size={13} />
              <input value={allowQuery} onChange={(e) => setAllowQuery(e.target.value)} placeholder="filter by path…" />
            </div>
            <button className="btn" onClick={toggleAllShown} disabled={shownEps.length === 0}>
              {allShownSelected ? "Deselect" : "Select"} {shownEps.length} shown
            </button>
            <span className="rt-selcount">{allow.size} selected</span>
            {allow.size > 0 && <button className="btn ghost" onClick={() => setAllow(new Set())}><X size={13} /> Clear</button>}
          </div>
          <div className="rt-allowbox">
            {shownEps.map((key) => {
              const endsSession = sessionEnders.has(key);
              return (
                <label
                  key={key}
                  className={`rt-check ${key.startsWith("GET ") && !endsSession ? "" : "mut"}`}
                  title={endsSession ? "ends the session — testing it logs the token out; tick to opt in" : undefined}
                >
                  <input
                    type="checkbox"
                    checked={allow.has(key)}
                    onChange={(e) =>
                      setAllow((s) => {
                        const next = new Set(s);
                        if (e.target.checked) next.add(key);
                        else next.delete(key);
                        return next;
                      })
                    }
                  />
                  <span className="route">{key}</span>
                  {endsSession && <span className="rt-tag">logout</span>}
                </label>
              );
            })}
            {shownEps.length === 0 && <div className="rt-allowempty">no endpoints match "{allowQuery}"</div>}
          </div>
        </div>
      )}

      <div className="rt-run">
        <button className="btn primary" onClick={run} disabled={running}>
          <Play size={13} /> {running ? "Running…" : "Run runtime test"}
        </button>
        {error && <span className="rt-err">{error}</span>}
      </div>
    </div>
  );
}

