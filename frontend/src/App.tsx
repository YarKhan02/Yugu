import { useState } from "react";
import { useScan } from "./lib/api";
import { Sidebar, type View } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { Inspector, type Selection } from "./components/Inspector";
import { Overview } from "./views/Overview";
import { Endpoints } from "./views/Endpoints";
import { Database } from "./views/Database";
import { Findings } from "./views/Findings";
import { AccessGraph } from "./views/AccessGraph";
import { RuntimeTests } from "./views/RuntimeTests";
import { Fuzz } from "./views/Fuzz";
import { ScanHistory } from "./views/ScanHistory";
import { Unavailable } from "./views/Unavailable";

export default function App() {
  const load = useScan();
  const [view, setView] = useState<View>("overview");
  const [query, setQuery] = useState("");
  const [selection, setSelection] = useState<Selection>(null);
  const [collapsed, setCollapsed] = useState(false);
  const [focus, setFocus] = useState<string | null>(null);

  if (load.state === "loading") {
    return <div className="loading"><div className="spinner" /><div>Loading scan…</div></div>;
  }
  if (load.state === "error") {
    return (
      <div className="errbox">
        <div>
          <div className="big">Could not load the scan</div>
          <div style={{ color: "var(--muted)" }}>{load.error}</div>
          <div style={{ color: "var(--muted)", marginTop: 8, fontSize: 12.5 }}>
            Is the server running? Start it with <code className="mono">pathwise serve</code>.
          </div>
        </div>
      </div>
    );
  }

  const scan = load.data;

  // go navigates and, when an endpoint is named, focuses it in the graph.
  const go = (v: View, endpoint?: string) => {
    setView(v);
    if (endpoint) {
      setSelection({ kind: "endpoint", id: endpoint });
      setFocus(endpoint);
    }
  };

  const body = () => {
    switch (view) {
      case "overview": return <Overview scan={scan} go={go} />;
      case "graph": return <AccessGraph scan={scan} focus={focus} selection={selection} onSelect={setSelection} />;
      case "endpoints": return <Endpoints scan={scan} query={query} selection={selection} onSelect={setSelection} />;
      case "database": return <Database scan={scan} query={query} selection={selection} onSelect={setSelection} />;
      case "findings": return <Findings scan={scan} query={query} go={go} />;
      case "runtime": return <RuntimeTests scan={scan} go={go} />;
      case "fuzz": return <Fuzz scan={scan} />;
      case "history": return <ScanHistory scan={scan} go={go} />;
      case "git": return <Unavailable title="Git comparison" reason="Diffing authorization between two revisions is Phase 7 and needs at least two stored scans." />;
      case "settings": return <Unavailable title="Settings" reason="There is nothing to configure here yet." />;
    }
  };

  const showInspector = selection !== null && (view === "graph" || view === "endpoints" || view === "database");

  return (
    <div className={`shell ${collapsed ? "collapsed" : ""}`}>
      <Sidebar view={view} onNavigate={(v) => { setView(v); }} scan={scan} />
      <div className="main">
        <TopBar view={view} scan={scan} query={query} onQuery={setQuery} onToggleSidebar={() => setCollapsed((c) => !c)} />
        <div className={`content ${view === "graph" ? "graphpage" : ""}`}>
          {view === "graph" ? <div className="graphwrap">{body()}</div> : body()}
        </div>
      </div>
      {showInspector && (
        <div className="inspector-drawer">
          <Inspector selection={selection} scan={scan} onClose={() => setSelection(null)} onSelect={setSelection} />
        </div>
      )}
    </div>
  );
}
