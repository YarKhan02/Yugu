import { Search, PanelLeft } from "lucide-react";
import type { View } from "./Sidebar";
import type { Scan } from "../lib/types";

const titles: Record<View, string> = {
  overview: "Overview",
  graph: "Access Graph",
  endpoints: "Endpoints",
  database: "Database",
  findings: "Findings",
  runtime: "Runtime Tests",
  fuzz: "Fuzzing",
  history: "Scan History",
  git: "Git Comparison",
  settings: "Settings",
};

export function TopBar({
  view, scan, query, onQuery, onToggleSidebar,
}: {
  view: View;
  scan: Scan;
  query: string;
  onQuery: (q: string) => void;
  onToggleSidebar: () => void;
}) {
  return (
    <header className="topbar">
      <button className="iconbtn" onClick={onToggleSidebar} title="Toggle sidebar" aria-label="Toggle sidebar">
        <PanelLeft size={15} strokeWidth={1.8} />
      </button>
      <div className="crumbs">
        <span>{scan.project}</span>
        <span className="sep">/</span>
        <span className="here">{titles[view]}</span>
      </div>
      <div className="spacer" />
      <label className="search" title="Search endpoints, tables, findings">
        <Search size={14} strokeWidth={1.8} />
        <input
          value={query}
          placeholder="Search endpoints, tables, findings…"
          onChange={(e) => onQuery(e.target.value)}
        />
      </label>
      <span className="scanchip">{scan.schemaSource === "none" ? "no schema" : scan.schemaSource}</span>
    </header>
  );
}
