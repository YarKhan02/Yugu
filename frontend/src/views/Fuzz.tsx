import { useMemo, useState } from "react";
import { Bug, Check, Play, X, Search } from "lucide-react";
import type { Scan, FuzzFinding } from "../lib/types";
import { runFuzz } from "../lib/api";

// Methods the fuzzer mutates. GET endpoints are not fuzzed directly — they are
// used internally as read-backs to verify what a write did.
const WRITE_METHODS = ["POST", "PUT", "PATCH", "DELETE"];

// kindLabel renders a break kind as a short human phrase.
const kindLabel: Record<string, string> = {
  endpoint_crash: "Crash (5xx)",
  write_read_inconsistency: "Accepted bad input, read failed",
  write_not_persisted: "Write not persisted",
  validation_asymmetry: "Validation asymmetry",
};

export function Fuzz({ scan }: { scan: Scan }) {
  const [breaks, setBreaks] = useState<FuzzFinding[] | null>(null);

  return (
    <div className="page">
      <div className="pagehead">
        <h1>Active fuzzing</h1>
        <p>
          Generate valid and invalid payloads for write endpoints, fire them at the running app, and
          read each resource back to find where it breaks — a body accepted without a required field,
          a payload that crashes the endpoint, or a write that is never persisted. This mutates data in
          the target; point it at a disposable, non-production app. Breaks are recorded separately from
          the static findings and never merged with them.
        </p>
      </div>

      <RunForm scan={scan} onDone={setBreaks} />

      {breaks && (
        <>
          <div className={`rt-banner ${breaks.length > 0 ? "" : "ok"}`}>
            <div className="ic">{breaks.length > 0 ? <Bug size={20} /> : <Check size={20} />}</div>
            <div>
              <h3>
                Run recorded — {breaks.length} break{breaks.length === 1 ? "" : "s"}
              </h3>
              <p>
                {breaks.length > 0
                  ? "Each break is a payload the app handled inconsistently. Review the detail for what was sent and what the app did."
                  : "No behavioral breaks on the selected endpoints with the generated payloads. A clean run is not a guarantee — only the payloads tried were exercised."}
              </p>
            </div>
          </div>

          {breaks.length > 0 && (
            <div className="panelcard" style={{ marginTop: 12 }}>
              <table className="fz-table">
                <thead>
                  <tr><th>Endpoint</th><th>Break</th><th>Payload</th><th>Detail</th></tr>
                </thead>
                <tbody>
                  {breaks.map((b, i) => (
                    <tr key={i}>
                      <td><code>{b.endpoint}</code></td>
                      <td><span className="fz-kind">{kindLabel[b.kind] ?? b.kind}</span></td>
                      <td><code>{b.payload}</code></td>
                      <td className="fz-detail">{b.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// RunForm collects the base URL, a single bearer token, and which write
// endpoints to fuzz, then asks the server to run. The token is typed here and
// sent to the target only; it is never stored.
function RunForm({ scan, onDone }: { scan: Scan; onDone: (r: FuzzFinding[]) => void }) {
  const [baseUrl, setBaseUrl] = useState("http://localhost:8080");
  const [token, setToken] = useState("");
  const [model, setModel] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [methodFilter, setMethodFilter] = useState<Set<string>>(new Set());
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");

  // Only write endpoints are fuzzable; GETs serve as read-backs.
  const writeEps = useMemo(() => {
    const seen = new Set<string>();
    for (const e of scan.endpoints) {
      const m = e.method.toUpperCase();
      if (WRITE_METHODS.includes(m)) seen.add(`${m} ${e.path}`);
    }
    return [...seen].sort();
  }, [scan.endpoints]);

  const methodCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const k of writeEps) {
      const m = k.split(" ", 1)[0];
      c[m] = (c[m] ?? 0) + 1;
    }
    return c;
  }, [writeEps]);
  const methods = useMemo(() => Object.keys(methodCounts).sort(), [methodCounts]);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return writeEps.filter(
      (k) =>
        (methodFilter.size === 0 || methodFilter.has(k.split(" ", 1)[0])) &&
        (!q || k.toLowerCase().includes(q)),
    );
  }, [writeEps, query, methodFilter]);

  const allShownSelected = shown.length > 0 && shown.every((k) => selected.has(k));
  const toggleAllShown = () =>
    setSelected((s) => {
      const next = new Set(s);
      if (allShownSelected) shown.forEach((k) => next.delete(k));
      else shown.forEach((k) => next.add(k));
      return next;
    });
  const toggleMethod = (m: string) =>
    setMethodFilter((s) => {
      const next = new Set(s);
      if (next.has(m)) next.delete(m);
      else next.add(m);
      return next;
    });

  const run = async () => {
    setError("");
    setRunning(true);
    try {
      // An empty selection means every write endpoint (the server's default).
      const r = await runFuzz({ baseUrl: baseUrl.trim(), token: token.trim(), model: model.trim(), endpoints: [...selected] });
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

      <label className="rt-field">
        <span>Bearer token <em>(sent to the target only, never stored; leave empty to fuzz unauthenticated)</em></span>
        <input type="password" value={token} onChange={(e) => setToken(e.target.value)} placeholder="token (empty = unauthenticated)" />
      </label>

      <label className="rt-field">
        <span>Ollama model <em>(optional — e.g. llama3; adds AI-generated adversarial payloads via local Ollama. Leave empty for deterministic payloads only)</em></span>
        <input value={model} onChange={(e) => setModel(e.target.value)} placeholder="llama3 (empty = deterministic only)" />
      </label>

      {writeEps.length > 0 ? (
        <div className="rt-field">
          <span>Endpoints to fuzz <em>(write methods only — GET endpoints are used as read-backs; none selected means all write endpoints)</em></span>
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
              <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="filter by path…" />
            </div>
            <button className="btn" onClick={toggleAllShown} disabled={shown.length === 0}>
              {allShownSelected ? "Deselect" : "Select"} {shown.length} shown
            </button>
            <span className="rt-selcount">{selected.size || "all"} selected</span>
            {selected.size > 0 && <button className="btn ghost" onClick={() => setSelected(new Set())}><X size={13} /> Clear</button>}
          </div>
          <div className="rt-allowbox">
            {shown.map((key) => (
              <label key={key} className="rt-check mut">
                <input
                  type="checkbox"
                  checked={selected.has(key)}
                  onChange={(e) =>
                    setSelected((s) => {
                      const next = new Set(s);
                      if (e.target.checked) next.add(key);
                      else next.delete(key);
                      return next;
                    })
                  }
                />
                <span className="route">{key}</span>
              </label>
            ))}
            {shown.length === 0 && <div className="rt-allowempty">no write endpoints match "{query}"</div>}
          </div>
        </div>
      ) : (
        <div className="rt-field"><em>This scan found no write endpoints to fuzz.</em></div>
      )}

      <div className="rt-run">
        <button className="btn primary" onClick={run} disabled={running}>
          <Play size={13} /> {running ? "Fuzzing…" : "Run fuzzer"}
        </button>
        {error && <span className="rt-err">{error}</span>}
      </div>
    </div>
  );
}
