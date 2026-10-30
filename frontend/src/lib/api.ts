import { useEffect, useState } from "react";
import type { Scan, RuntimeTest, FuzzFinding } from "./types";

// runTests asks the local server to exercise the running app as the supplied
// identities and returns the outcomes. Tokens are sent to localhost only, used
// in memory for the run, and never persisted — the same contract as the
// `pathwise test` CLI.
export async function runTests(req: {
  baseUrl: string;
  identities: { role: string; token: string }[];
  endpoints: string[];
}): Promise<RuntimeTest[]> {
  const r = await fetch("api/test", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  if (!r.ok) throw new Error((await r.text()) || `server returned ${r.status}`);
  return r.json();
}

// runFuzz asks the local server to actively fuzz the selected write endpoints of
// the running app and returns the behavioral breaks found. The token is sent to
// localhost only, used in memory for the run, and never persisted. An empty
// endpoints list means every write endpoint.
export async function runFuzz(req: {
  baseUrl: string;
  token: string;
  model: string;
  endpoints: string[];
}): Promise<FuzzFinding[]> {
  const r = await fetch("api/fuzz", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  if (!r.ok) throw new Error((await r.text()) || `server returned ${r.status}`);
  return r.json();
}

export type Load<T> =
  | { state: "loading" }
  | { state: "error"; error: string }
  | { state: "ready"; data: T };

// useScan fetches the current scan from the local server once. There is no
// silent fallback to fixtures: a failed request surfaces as an error state the
// UI shows plainly, because fake scan data would be worse than none.
export function useScan(): Load<Scan> {
  const [load, setLoad] = useState<Load<Scan>>({ state: "loading" });

  useEffect(() => {
    let live = true;
    fetch("api/scan")
      .then((r) => {
        if (!r.ok) throw new Error(`server returned ${r.status}`);
        return r.json();
      })
      .then((data: Scan) => live && setLoad({ state: "ready", data }))
      .catch((e: unknown) =>
        live && setLoad({ state: "error", error: e instanceof Error ? e.message : String(e) }),
      );
    return () => {
      live = false;
    };
  }, []);

  return load;
}

// roleColorVar maps a role to one of the validated categorical palette slots,
// by its index in the scan's sorted role list, so color follows the role.
export function roleColorVar(role: string, roles: string[]): string {
  const i = roles.indexOf(role);
  return i >= 0 && i < 8 ? `var(--role-${i})` : "var(--muted)";
}
