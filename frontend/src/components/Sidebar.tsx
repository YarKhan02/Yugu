import {
  LayoutDashboard, Share2, Route, Database, ShieldAlert,
  FlaskConical, History, GitCompare, Settings, Shield, Bug,
} from "lucide-react";
import type { Scan } from "../lib/types";

export type View =
  | "overview" | "graph" | "endpoints" | "database" | "findings"
  | "runtime" | "fuzz" | "history" | "git" | "settings";

interface Item {
  id: View;
  label: string;
  icon: typeof Route;
  ready: boolean;
}

const primary: Item[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard, ready: true },
  { id: "graph", label: "Access Graph", icon: Share2, ready: true },
  { id: "endpoints", label: "Endpoints", icon: Route, ready: true },
  { id: "database", label: "Database", icon: Database, ready: true },
  { id: "findings", label: "Findings", icon: ShieldAlert, ready: true },
];

const verify: Item[] = [
  { id: "runtime", label: "Runtime Tests", icon: FlaskConical, ready: true },
  { id: "fuzz", label: "Fuzzing", icon: Bug, ready: true },
  { id: "history", label: "Scan History", icon: History, ready: true },
  { id: "git", label: "Git Comparison", icon: GitCompare, ready: false },
  { id: "settings", label: "Settings", icon: Settings, ready: false },
];

export function Sidebar({
  view, onNavigate, scan,
}: {
  view: View;
  onNavigate: (v: View) => void;
  scan: Scan;
}) {
  const row = (it: Item) => {
    const Icon = it.icon;
    return (
      <button
        key={it.id}
        className={`navitem ${view === it.id ? "active" : ""} ${it.ready ? "" : "disabled"}`}
        onClick={() => it.ready && onNavigate(it.id)}
        disabled={!it.ready}
        title={it.ready ? it.label : `${it.label} — not available yet`}
      >
        <Icon size={16} strokeWidth={1.8} />
        <span>{it.label}</span>
        {!it.ready && <span className="tag">soon</span>}
      </button>
    );
  };

  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="mark"><Shield size={14} strokeWidth={2.2} /></span>
        <b>PathWise</b>
      </div>
      <div className="project">
        <div className="pname">{scan.project}</div>
        <div className="prev">
          scan <code>{shortScan(scan.scanId)}</code>
        </div>
      </div>
      <nav>
        {primary.map(row)}
        <div className="nav-group-label">Verification</div>
        {verify.map(row)}
      </nav>
    </aside>
  );
}

function shortScan(id: string): string {
  // scan_<millis>_<rand> → show the trailing short id
  const parts = id.split("_");
  return parts.length >= 3 ? parts[2].slice(0, 8) : id.slice(0, 10);
}
