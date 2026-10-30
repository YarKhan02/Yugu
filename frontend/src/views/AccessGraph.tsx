import { useEffect, useMemo, useRef, useState, useCallback, memo } from "react";
import {
  ReactFlow, ReactFlowProvider, Background, BackgroundVariant, Controls, MiniMap,
  Handle, Position, useReactFlow, useNodesState, MarkerType,
  type Node, type Edge, type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import ELK from "elkjs/lib/elk.bundled.js";
import { Search, X, KeyRound, Link2 } from "lucide-react";
import type { Scan, Endpoint, TableInfo, ColumnInfo } from "../lib/types";
import type { Selection } from "../components/Inspector";
import { MethodBadge } from "../components/primitives";

// AccessGraph is the endpoint ↔ table map. The Graph view is an infinite,
// pannable/zoomable ERD canvas (React Flow + elkjs layout); the Matrix view and
// all filters are unchanged. Edges between endpoints and tables are hidden by
// default and revealed only for the active (hovered/pinned) item or domain, so
// hundreds of relationships never draw at once. Everything is a projection of
// /api/scan — nothing is hardcoded.

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const COL_LIMIT = 8;
const CLUSTER_W = 300, PILL_H = 28, CLUSTER_HEAD = 34, CLUSTER_PAD = 12;
const TABLE_W = 238, ROW_H = 22, TABLE_HEAD = 34, MORE_H = 22;

function domainOf(path: string): string {
  const seg = path.split("/").filter(Boolean)[0];
  return seg && !seg.startsWith("{") ? seg : "(root)";
}
export function AccessGraph({
  scan, focus, selection, onSelect,
}: {
  scan: Scan; focus: string | null; selection: Selection; onSelect: (s: Selection) => void;
}) {
  const [search, setSearch] = useState("");
  const [methodF, setMethodF] = useState<Set<string>>(new Set());
  const [domainF, setDomainF] = useState<Set<string>>(new Set());
  const [collapsedClusters, setCollapsedClusters] = useState<Set<string>>(new Set());
  const [expandedTables, setExpandedTables] = useState<Set<string>>(new Set());
  const [hover, setHover] = useState<Selection>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  const { epTables, tableEps } = useMemo(() => {
    const et = new Map<string, string[]>(), te = new Map<string, string[]>();
    for (const e of scan.endpoints) {
      et.set(e.id, e.tables.map((t) => t.table));
      for (const t of e.tables) te.set(t.table, [...(te.get(t.table) ?? []), e.id]);
    }
    return { epTables: et, tableEps: te };
  }, [scan]);

  const domains = useMemo(() => [...new Set(scan.endpoints.map((e) => domainOf(e.path)))].sort(), [scan]);

  const q = search.trim().toLowerCase();
  const epHit = useCallback((e: Endpoint) => `${e.method} ${e.path}`.toLowerCase().includes(q), [q]);
  const tblHit = useCallback((t: TableInfo) => t.name.toLowerCase().includes(q), [q]);

  const visibleEp = useMemo(() => {
    const matched = q ? new Set(scan.tables.filter(tblHit).map((t) => t.name)) : null;
    const set = new Set<string>();
    for (const e of scan.endpoints) {
      if (methodF.size && !methodF.has(e.method.toUpperCase())) continue;
      if (domainF.size && !domainF.has(domainOf(e.path))) continue;
      if (q && !epHit(e) && !(matched && (epTables.get(e.id) ?? []).some((t) => matched.has(t)))) continue;
      set.add(e.id);
    }
    return set;
  }, [scan, methodF, domainF, q, epHit, tblHit, epTables]);

  const visibleTbl = useMemo(() => {
    const set = new Set<string>();
    for (const t of scan.tables) {
      const touched = (tableEps.get(t.name) ?? []).some((id) => visibleEp.has(id));
      if (q) {
        if (tblHit(t) || (tableEps.get(t.name) ?? []).some((id) => visibleEp.has(id) && epHit(byId(scan, id)))) set.add(t.name);
      } else if (touched) set.add(t.name);
    }
    return set;
  }, [scan, visibleEp, q, tblHit, epHit, tableEps]);

  const active = hover ?? selection;
  const related = useMemo(() => relatedSet(active, epTables, tableEps), [active, epTables, tableEps]);

  useEffect(() => {
    const onKey = (ev: KeyboardEvent) => {
      const typing = document.activeElement?.tagName === "INPUT";
      if (ev.key === "/" && !typing) { ev.preventDefault(); searchRef.current?.focus(); return; }
      if (ev.key === "Escape") { setSearch(""); onSelect(null); setHover(null); (document.activeElement as HTMLElement)?.blur?.(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onSelect]);

  const allTables = useMemo(() => scan.tables.map((t) => t.name), [scan]);
  const expandAll = () => { setCollapsedClusters(new Set()); setExpandedTables(new Set(allTables)); };
  const collapseAll = () => { setCollapsedClusters(new Set(domains)); setExpandedTables(new Set()); };

  return (
    <div className="ag">
      <div className="ag-toolbar">
        <div className="search ag-search">
          <Search size={13} />
          <input ref={searchRef} value={search} placeholder="Search path, method or table  ( / )"
            onChange={(e) => setSearch(e.target.value)} />
          {search && <button className="iconbtn" onClick={() => setSearch("")}><X size={13} /></button>}
        </div>
        <div className="ag-chips">
          {METHODS.map((m) => (
            <button key={m} className={`mchip m-${m.toLowerCase()} ${methodF.has(m) ? "on" : ""}`}
              onClick={() => setMethodF(toggle(methodF, m))}>{m}</button>
          ))}
        </div>
      </div>

      <div className="ag-domainchips">
        {domains.map((d) => (
          <button key={d} className={`dchip ${domainF.has(d) ? "on" : ""}`} onClick={() => setDomainF(toggle(domainF, d))}>
            /{d === "(root)" ? "" : d}
          </button>
        ))}
        {(methodF.size > 0 || domainF.size > 0) && (
          <button className="dchip clear" onClick={() => { setMethodF(new Set()); setDomainF(new Set()); }}><X size={11} /> clear filters</button>
        )}
        <span className="ag-spacer" />
        <button className="linklike" onClick={expandAll}>Expand all</button>
        <button className="linklike" onClick={collapseAll}>Collapse all</button>
      </div>

      <ReactFlowProvider>
        <GraphCanvas scan={scan} visibleEp={visibleEp} visibleTbl={visibleTbl}
          tableEps={tableEps} epTables={epTables} domainF={domainF} q={q}
          active={active} related={related} selection={selection} onSelect={onSelect} setHover={setHover}
          collapsedClusters={collapsedClusters} setCollapsedClusters={setCollapsedClusters}
          expandedTables={expandedTables} setExpandedTables={setExpandedTables} focus={focus} />
      </ReactFlowProvider>
    </div>
  );
}

function byId(scan: Scan, id: string): Endpoint { return scan.endpoints.find((e) => e.id === id)!; }
function toggle(s: Set<string>, v: string): Set<string> { const n = new Set(s); n.has(v) ? n.delete(v) : n.add(v); return n; }
function relatedSet(active: Selection, epTables: Map<string, string[]>, tableEps: Map<string, string[]>) {
  const eps = new Set<string>(), tbls = new Set<string>();
  if (active?.kind === "endpoint") { eps.add(active.id); for (const t of epTables.get(active.id) ?? []) tbls.add(t); }
  else if (active?.kind === "table") { tbls.add(active.name); for (const e of tableEps.get(active.name) ?? []) eps.add(e); }
  return { eps, tbls };
}

// ======================= React Flow canvas ============================

const elk = new ELK();

type NodeData = {
  kind: "cluster" | "endpoint" | "table";
  label?: string; count?: number; method?: string; path?: string; flagged?: boolean;
  table?: TableInfo; expanded?: boolean; onToggle?: () => void; collapsed?: boolean;
};

function tableHeight(t: TableInfo, expanded: boolean): number {
  const cols = t.columns ?? [];
  const shown = expanded ? cols.length : Math.min(cols.length, COL_LIMIT);
  return TABLE_HEAD + Math.max(shown, 1) * ROW_H + (cols.length > COL_LIMIT ? MORE_H : 0);
}

function GraphCanvas(props: {
  scan: Scan; visibleEp: Set<string>; visibleTbl: Set<string>;
  tableEps: Map<string, string[]>; epTables: Map<string, string[]>; domainF: Set<string>; q: string;
  active: Selection; related: { eps: Set<string>; tbls: Set<string> };
  selection: Selection; onSelect: (s: Selection) => void; setHover: (s: Selection) => void;
  collapsedClusters: Set<string>; setCollapsedClusters: (s: Set<string>) => void;
  expandedTables: Set<string>; setExpandedTables: (s: Set<string>) => void; focus: string | null;
}) {
  const { scan, visibleEp, visibleTbl, tableEps, epTables, domainF, q, active, related,
    onSelect, setHover, collapsedClusters, setCollapsedClusters, expandedTables, setExpandedTables, focus } = props;
  const rf = useReactFlow();
  const [nodes, setNodes, onNodesChange] = useNodesState<Node<NodeData>>([]);
  const [lodMin, setLodMin] = useState(false);
  const activeRef = useRef(active), relatedRef = useRef(related), qRef = useRef(q);
  activeRef.current = active; relatedRef.current = related; qRef.current = q;

  // Clusters (domain → its visible endpoints) and visible tables.
  const clusters = useMemo(() => {
    const by = new Map<string, Endpoint[]>();
    for (const e of scan.endpoints) {
      if (!visibleEp.has(e.id)) continue;
      const d = domainOf(e.path); by.set(d, [...(by.get(d) ?? []), e]);
    }
    for (const [, l] of by) l.sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
    return [...by.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [scan, visibleEp]);
  const tables = useMemo(() => scan.tables.filter((t) => visibleTbl.has(t.name)), [scan, visibleTbl]);

  const toggleTable = useCallback((name: string) => {
    setExpandedTables(toggle(expandedTables, name));
  }, [expandedTables, setExpandedTables]);

  // ---- Layout (elkjs). Runs only on structural change, never on hover. ----
  const structuralKey = useMemo(() => JSON.stringify({
    c: clusters.map(([d, l]) => [d, collapsedClusters.has(d), l.length]),
    t: tables.map((t) => [t.name, expandedTables.has(t.name), (t.columns ?? []).length]),
  }), [clusters, tables, collapsedClusters, expandedTables]);

  useEffect(() => {
    let cancelled = false;
    const children: any[] = [];
    const edges: any[] = [];

    for (const [d, list] of clusters) {
      const collapsed = collapsedClusters.has(d);
      children.push({ id: `g:${d}`, width: CLUSTER_W, height: collapsed ? CLUSTER_HEAD : CLUSTER_HEAD + list.length * PILL_H + CLUSTER_PAD });
    }
    for (const t of tables) children.push({ id: `t:${t.name}`, width: TABLE_W, height: tableHeight(t, expandedTables.has(t.name)) });

    const visTbl = new Set(tables.map((t) => t.name));
    // cluster → table (usage) pulls clusters toward the tables they use; weight
    // by shared endpoints so heavily-used tables are pulled to the centre.
    for (const [d, list] of clusters) {
      const counts = new Map<string, number>();
      for (const e of list) for (const t of (epTables.get(e.id) ?? [])) if (visTbl.has(t)) counts.set(t, (counts.get(t) ?? 0) + 1);
      for (const [t] of counts) edges.push({ id: `l:${d}:${t}`, sources: [`g:${d}`], targets: [`t:${t}`] });
    }
    // FK edges contribute real schema structure to the layout too.
    for (const t of tables) for (const c of (t.columns ?? [])) {
      if (c.foreignKey) { const to = c.foreignKey.split(".")[0]; if (visTbl.has(to) && to !== t.name) edges.push({ id: `f:${t.name}:${c.name}`, sources: [`t:${t.name}`], targets: [`t:${to}`] }); }
    }

    // Layered guarantees no node overlap and reads left→right: endpoint clusters
    // flow into the tables they use. Generous inter-layer spacing and spline
    // routing keep it legible with dozens of large nodes.
    const graph = {
      id: "root",
      layoutOptions: {
        "elk.algorithm": "org.eclipse.elk.layered",
        "elk.direction": "RIGHT",
        "elk.spacing.nodeNode": "48",
        "elk.layered.spacing.nodeNodeBetweenLayers": "160",
        "elk.layered.spacing.edgeNodeBetweenLayers": "48",
        "elk.layered.nodePlacement.strategy": "BRANDES_KOEPF",
        "elk.layered.considerModelOrder.strategy": "NODES_AND_EDGES",
        "elk.edgeRouting": "SPLINES",
      },
      children, edges,
    };

    elk.layout(graph).then((res) => {
      if (cancelled) return;
      const pos = new Map<string, { x: number; y: number }>();
      for (const c of res.children ?? []) pos.set(c.id, { x: c.x ?? 0, y: c.y ?? 0 });

      const next: Node<NodeData>[] = [];
      for (const [d, list] of clusters) {
        const collapsed = collapsedClusters.has(d);
        const p = pos.get(`g:${d}`) ?? { x: 0, y: 0 };
        next.push({
          id: `g:${d}`, type: "cluster", position: p, draggable: true,
          style: { width: CLUSTER_W, height: collapsed ? CLUSTER_HEAD : CLUSTER_HEAD + list.length * PILL_H + CLUSTER_PAD },
          data: { kind: "cluster", label: d === "(root)" ? "/" : `/${d}`, count: list.length, collapsed,
            onToggle: () => setCollapsedClusters(toggle(collapsedClusters, d)) },
        });
        if (!collapsed) list.forEach((e, i) => next.push({
          id: `e:${e.id}`, type: "endpoint", parentId: `g:${d}`, extent: "parent",
          position: { x: 12, y: CLUSTER_HEAD + i * PILL_H }, draggable: false,
          data: { kind: "endpoint", method: e.method, path: e.path, flagged: e.findings.length > 0 },
        }));
      }
      for (const t of tables) {
        const p = pos.get(`t:${t.name}`) ?? { x: 0, y: 0 };
        next.push({
          id: `t:${t.name}`, type: "table", position: p, draggable: true,
          data: { kind: "table", table: t, count: (tableEps.get(t.name) ?? []).length,
            expanded: expandedTables.has(t.name), onToggle: () => toggleTable(t.name) },
        });
      }
      setNodes(applyClasses(next, activeRef.current, relatedRef.current, qRef.current, scan));
      window.requestAnimationFrame(() => rf.fitView({ padding: 0.15, duration: 300 }));
    }).catch(() => { /* layout failure leaves the previous graph in place */ });

    return () => { cancelled = true; };
  }, [structuralKey]); // eslint-disable-line react-hooks/exhaustive-deps

  // ---- Highlight/dim without re-layout: just remap classNames. ----
  useEffect(() => {
    setNodes((prev) => applyClasses(prev, active, related, q, scan));
  }, [active, related, q]); // eslint-disable-line react-hooks/exhaustive-deps

  // ---- Edges: FK always; endpoint↔table only for the active item. ----
  const edges = useMemo<Edge[]>(() => {
    const out: Edge[] = [];
    const visTbl = new Set(tables.map((t) => t.name));
    const dimAll = !!active;
    for (const t of tables) {
      const expanded = expandedTables.has(t.name);
      for (const c of (t.columns ?? [])) {
        if (!c.foreignKey) continue;
        const [toT, toC] = c.foreignKey.split(".");
        if (!visTbl.has(toT) || toT === t.name) continue;
        void toC; void expanded;
        out.push({
          id: `fk:${t.name}.${c.name}`, source: `t:${t.name}`, target: `t:${toT}`,
          sourceHandle: "s:node", targetHandle: "t:node",
          className: `ag-fkedge${dimAll ? " dim" : ""}`, zIndex: 1,
          markerEnd: { type: MarkerType.ArrowClosed, width: 11, height: 11 },
        });
      }
    }
    // Active endpoint → its tables, or active table ← its endpoints.
    const addEP = (e: Endpoint) => {
      for (const tr of e.tables) {
        if (!visTbl.has(tr.table)) continue;
        const write = (tr.writeColumns?.length ?? 0) > 0 || tr.operations.some((o) => o !== "SELECT");
        out.push({
          id: `a:${e.id}:${tr.table}`, source: `e:${e.id}`, target: `t:${tr.table}`,
          targetHandle: "t:node", className: `ag-aedge ${write ? "w" : "r"}`, zIndex: 5, animated: false,
          markerEnd: { type: MarkerType.ArrowClosed, width: 13, height: 13 },
        });
      }
    };
    if (active?.kind === "endpoint") { const e = scan.endpoints.find((x) => x.id === active.id); if (e) addEP(e); }
    else if (active?.kind === "table") {
      for (const id of tableEps.get(active.name) ?? []) { if (!visibleEp.has(id)) continue; const e = byId(scan, id); addEP(e); }
    }
    return out;
  }, [scan, tables, active, expandedTables, tableEps, visibleEp]);

  // Search → pan to first match. Domain filter → fit the visible result.
  useEffect(() => {
    if (!q) return;
    const n = nodes.find((x) => x.className?.includes("ag-hit"));
    if (n) rf.fitView({ nodes: [{ id: n.id }], padding: 0.4, duration: 400, maxZoom: 1.4 });
  }, [q, nodes, rf]);
  useEffect(() => {
    if (domainF.size) window.requestAnimationFrame(() => rf.fitView({ padding: 0.2, duration: 400 }));
  }, [domainF, rf]);
  useEffect(() => {
    if (!focus) return;
    onSelect({ kind: "endpoint", id: focus });
    const n = nodes.find((x) => x.id === `e:${focus}`);
    if (n) rf.fitView({ nodes: [{ id: n.id }], padding: 0.5, duration: 400, maxZoom: 1.5 });
  }, [focus]); // eslint-disable-line react-hooks/exhaustive-deps

  const onNodeClick = useCallback((_: unknown, n: Node<NodeData>) => {
    if (n.data.kind === "endpoint") onSelect({ kind: "endpoint", id: n.id.slice(2) });
    else if (n.data.kind === "table") onSelect({ kind: "table", name: n.id.slice(2) });
  }, [onSelect]);
  const onNodeEnter = useCallback((_: unknown, n: Node<NodeData>) => {
    if (n.data.kind === "endpoint") setHover({ kind: "endpoint", id: n.id.slice(2) });
    else if (n.data.kind === "table") setHover({ kind: "table", name: n.id.slice(2) });
  }, [setHover]);

  return (
    <div className={`ag-rf ${lodMin ? "lod-min" : ""}`}>
      <ReactFlow
        nodes={nodes} edges={edges} nodeTypes={NODE_TYPES}
        onNodesChange={onNodesChange} onNodeClick={onNodeClick}
        onNodeMouseEnter={onNodeEnter} onNodeMouseLeave={() => setHover(null)}
        onPaneClick={() => onSelect(null)}
        onMove={(_, vp) => { const min = vp.zoom < 0.5; setLodMin((p) => (p !== min ? min : p)); }}
        minZoom={0.05} maxZoom={3} fitView onlyRenderVisibleElements proOptions={{ hideAttribution: true }}
        defaultEdgeOptions={{ type: "default" }} nodesConnectable={false} elementsSelectable>
        <Background variant={BackgroundVariant.Dots} gap={22} size={1} />
        <MiniMap pannable zoomable nodeColor={miniColor} nodeStrokeWidth={2} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

function miniColor(n: Node<NodeData>): string {
  if (n.data.kind === "table") return "#c3ccf4";
  if (n.data.kind === "cluster") return "#e7e7e3";
  return "#8aa0e8";
}

// applyClasses recomputes each node's className from the active selection and
// search, preserving positions (so dragging and layout are never disturbed).
function applyClasses(nodes: Node<NodeData>[], active: Selection, related: { eps: Set<string>; tbls: Set<string> }, q: string, scan: Scan): Node<NodeData>[] {
  const hit = (n: Node<NodeData>): boolean => {
    if (!q) return false;
    if (n.data.kind === "endpoint") { const e = scan.endpoints.find((x) => x.id === n.id.slice(2)); return !!e && `${e.method} ${e.path}`.toLowerCase().includes(q); }
    if (n.data.kind === "table") return n.id.slice(2).toLowerCase().includes(q);
    return false;
  };
  const rel = (n: Node<NodeData>): boolean => {
    if (!active) return false;
    if (n.data.kind === "endpoint") return related.eps.has(n.id.slice(2));
    if (n.data.kind === "table") return related.tbls.has(n.id.slice(2));
    if (n.data.kind === "cluster") { // a cluster stays lit if it holds a related endpoint
      const d = n.id.slice(2); return [...related.eps].some((id) => domainOf(byId(scan, id).path) === (d === "/" ? "(root)" : d.replace(/^\//, "")));
    }
    return false;
  };
  return nodes.map((n) => {
    let cls = "";
    if (q) cls = hit(n) ? "ag-hit" : "ag-dim";
    else if (active) cls = rel(n) ? "ag-rel" : (n.data.kind === "cluster" ? "" : "ag-dim");
    return n.className === cls ? n : { ...n, className: cls };
  });
}

// ---- custom nodes (module-level so nodeTypes stays stable) ----

const EndpointNode = memo(({ data }: NodeProps<Node<NodeData>>) => (
  <div className="rf-ep">
    <Handle type="source" position={Position.Right} id="s:node" className="h-hidden" />
    <MethodBadge method={data.method!} />
    <Path path={data.path!} />
    {data.flagged && <span className="rf-flag" title="has findings" />}
  </div>
));
EndpointNode.displayName = "EndpointNode";

const ClusterNode = memo(({ data }: NodeProps<Node<NodeData>>) => (
  <div className={`rf-cluster ${data.collapsed ? "collapsed" : ""}`}>
    <div className="rf-cluster-head" onClick={(e) => { e.stopPropagation(); data.onToggle?.(); }}>
      <span className="name">{data.label}</span>
      <span className="count">{data.count}</span>
    </div>
  </div>
));
ClusterNode.displayName = "ClusterNode";

const TableNode = memo(({ data }: NodeProps<Node<NodeData>>) => {
  const t = data.table!;
  const cols = t.columns ?? [];
  const expanded = data.expanded;
  const shown = expanded ? cols : cols.slice(0, COL_LIMIT);
  return (
    <div className="rf-table">
      <Handle type="target" position={Position.Left} id="t:node" className="h-hidden" />
      <Handle type="source" position={Position.Right} id="s:node" className="h-hidden" />
      <div className="rf-table-head">
        <span className="name">{t.name}</span>
        <span className="badge" title={`${data.count} endpoint(s)`}>{data.count}</span>
      </div>
      <div className="rf-cols">
        {cols.length === 0 && <div className="nocols">no columns in schema</div>}
        {shown.map((c) => <TableColRow key={c.name} c={c} table={t.name} />)}
        {cols.length > COL_LIMIT && (
          <button className="rf-more" onClick={(e) => { e.stopPropagation(); data.onToggle?.(); }}>
            {expanded ? "show less" : `show ${cols.length - COL_LIMIT} more`}
          </button>
        )}
      </div>
    </div>
  );
});
TableNode.displayName = "TableNode";

function TableColRow({ c, table }: { c: ColumnInfo; table: string }) {
  return (
    <div className="rf-col">
      <span className="cname">{c.name}</span>
      {c.primaryKey && <KeyRound size={10} className="ic-pk" aria-label="PK" />}
      {c.foreignKey && <Link2 size={10} className="ic-fk" aria-label={`FK → ${c.foreignKey}`} />}
      <span className="ctype" title={`${table}.${c.name} ${c.type}`}>{c.type}</span>
    </div>
  );
}

const NODE_TYPES = { endpoint: EndpointNode, cluster: ClusterNode, table: TableNode };

function Path({ path }: { path: string }) {
  const parts = path.split(/(\{[^}]+\})/g);
  return <span className="ag-path">{parts.map((p, i) => p.startsWith("{") ? <span key={i} className="param">{p}</span> : <span key={i}>{p}</span>)}</span>;
}
