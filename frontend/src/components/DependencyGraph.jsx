import { useEffect, useMemo, useRef, useState } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import { Maximize2, Minus, Plus, RotateCcw } from "lucide-react";
import { Button, STATUS_COLORS, STATUS_LABELS, shortName } from "./ui.jsx";

const STYLE = [
  {
    selector: "node",
    style: {
      "background-color": "data(color)",
      label: "data(label)",
      color: "#cbd5e1",
      "font-size": 9,
      "font-family": "Inter, system-ui, sans-serif",
      "text-valign": "bottom",
      "text-margin-y": 5,
      "text-wrap": "wrap",
      "text-max-width": 110,
      "text-background-color": "#020617",
      "text-background-opacity": 0.85,
      "text-background-padding": 2,
      "text-background-shape": "roundrectangle",
      "min-zoomed-font-size": 6,
      width: 16,
      height: 16,
      "border-width": 2,
      "border-color": "#020617",
    },
  },
  {
    selector: 'node[type = "project"]',
    style: {
      shape: "round-rectangle", width: 30, height: 22, "font-size": 10, "font-weight": 600, color: "#f8fafc",
    },
  },
  { selector: 'node[status = "vulnerable"]', style: { width: 22, height: 22, "border-color": "#7f1d1d", "border-width": 3 } },
  {
    selector: "edge",
    style: {
      width: 1.2, "line-color": "#334155", "target-arrow-color": "#334155",
      "target-arrow-shape": "triangle", "arrow-scale": 0.7, "curve-style": "bezier",
    },
  },
  { selector: "edge.risk", style: { "line-color": "#b45309", "target-arrow-color": "#b45309", width: 1.8 } },
  { selector: 'edge[scope = "development"]', style: { "line-style": "dashed" } },
  { selector: "edge[?inferred]", style: { "line-style": "dotted", "line-color": "#a78bfa", "target-arrow-color": "#a78bfa" } },
  { selector: ".hidden", style: { display: "none" } },
  { selector: "node.faded", style: { opacity: 0.25, "text-opacity": 0.5 } },
  { selector: "edge.faded", style: { opacity: 0.1 } },
  { selector: "node.hovered", style: { "border-color": "#94a3b8", "border-width": 3 } },
  { selector: "edge.path", style: { "line-color": "#f87171", "target-arrow-color": "#f87171", width: 2.5, opacity: 1 } },
  { selector: "node.selected", style: { "border-color": "#5eead4", "border-width": 4 } },
];

function nodeLabel(n) {
  if (n.type === "project") return n.label;
  const at = n.label.lastIndexOf("@");
  const name = at > 0 ? n.label.slice(0, at) : n.label;
  return `${shortName(name)}\n${n.version ?? "?"}`;
}

export default function DependencyGraph({ graph, filters, selectedId, onSelect, height = 600 }) {
  const cyRef = useRef(null);
  const [hover, setHover] = useState(null);
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;

  const elements = useMemo(() => {
    const status = Object.fromEntries(graph.nodes.map((n) => [n.id, n.status]));
    const risky = (id) => status[id] === "vulnerable" || status[id] === "affected";
    return [
      ...graph.nodes.map((n) => ({
        data: {
          id: n.id, label: nodeLabel(n), type: n.type, status: n.status, ecosystem: n.ecosystem ?? "",
          severity: n.severity ?? "", color: STATUS_COLORS[n.status],
          fullLabel: n.label, score: n.max_risk_score, priority: n.priority, advisories: n.vulnerabilities?.length ?? 0,
        },
      })),
      ...graph.edges.map((e) => ({
        data: { id: `${e.source}->${e.target}`, source: e.source, target: e.target, scope: e.scope, inferred: e.inferred },
        classes: risky(e.source) && risky(e.target) ? "risk" : "",
      })),
    ];
  }, [graph]);

  const layout = useMemo(() => (graph.nodes.length <= 160
    ? { name: "breadthfirst", directed: true, roots: graph.nodes.filter((n) => n.type === "project").map((n) => n.id), spacingFactor: 1.25, padding: 30, animate: false }
    : { name: "cose", animate: false, padding: 30, nodeRepulsion: 9000, idealEdgeLength: 70 }), [graph]);

  // Filters and selection are applied as CSS classes so the layout stays stable.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.elements().removeClass("hidden faded selected path");
      let keep = cy.nodes().filter((n) => n.data("type") === "project" || filters.statuses.has(n.data("status")));
      if (filters.ecosystem !== "all") keep = keep.filter((n) => n.data("type") === "project" || n.data("ecosystem") === filters.ecosystem);
      if (filters.severity !== "all") {
        const vuln = cy.nodes().filter((n) => n.data("status") === "vulnerable" && n.data("severity") === filters.severity);
        keep = keep.intersection(vuln.union(vuln.predecessors().nodes()));
      }
      cy.nodes().not(keep).addClass("hidden");
      if (selectedId) {
        const node = cy.getElementById(selectedId);
        if (node.nonempty()) {
          const up = node.predecessors();
          const down = node.successors();
          cy.elements().not(node.union(up).union(down)).addClass("faded");
          node.addClass("selected");
          up.edges().addClass("path");
        }
      }
    });
  }, [filters, selectedId, graph]);

  const fit = () => cyRef.current?.fit(cyRef.current.elements(":visible"), 30);

  return (
    <div className="relative">
      <div className="absolute right-3 top-3 z-10 flex flex-col gap-1.5">
        <Button size="sm" variant="secondary" onClick={() => cyRef.current?.zoom({ level: cyRef.current.zoom() * 1.25, renderedPosition: { x: cyRef.current.width() / 2, y: cyRef.current.height() / 2 } })} aria-label="Zoom in"><Plus className="h-3.5 w-3.5" /></Button>
        <Button size="sm" variant="secondary" onClick={() => cyRef.current?.zoom({ level: cyRef.current.zoom() / 1.25, renderedPosition: { x: cyRef.current.width() / 2, y: cyRef.current.height() / 2 } })} aria-label="Zoom out"><Minus className="h-3.5 w-3.5" /></Button>
        <Button size="sm" variant="secondary" onClick={fit} aria-label="Fit to view"><Maximize2 className="h-3.5 w-3.5" /></Button>
        <Button size="sm" variant="secondary" onClick={() => { onSelect(null); setTimeout(fit, 0); }} aria-label="Reset view"><RotateCcw className="h-3.5 w-3.5" /></Button>
      </div>
      <CytoscapeComponent
        key={graph.scan_id}
        elements={elements}
        stylesheet={STYLE}
        layout={layout}
        minZoom={0.15}
        maxZoom={3}
        style={{ width: "100%", height }}
        className="rounded-lg bg-slate-950 [background-image:radial-gradient(#1e293b_1px,transparent_1px)] [background-size:22px_22px]"
        cy={(cy) => {
          if (cyRef.current === cy) return;
          cyRef.current = cy;
          cy.on("tap", "node", (evt) => onSelectRef.current(evt.target.id()));
          cy.on("tap", (evt) => evt.target === cy && onSelectRef.current(null));
          cy.on("mouseover", "node", (evt) => {
            evt.target.addClass("hovered");
            cy.container().style.cursor = "pointer";
            const { x, y } = evt.target.renderedPosition();
            setHover({ ...evt.target.data(), x, y });
          });
          cy.on("mouseout", "node", (evt) => {
            evt.target.removeClass("hovered");
            cy.container().style.cursor = "";
            setHover(null);
          });
          cy.on("viewport", () => setHover(null));
        }}
      />
      {hover && (
        <div
          className="pointer-events-none absolute z-20 max-w-64 -translate-x-1/2 -translate-y-full rounded-lg border border-slate-700 bg-slate-900/95 px-3 py-2 text-xs shadow-xl"
          style={{ left: hover.x, top: hover.y - 16 }}
        >
          <p className="break-all font-mono text-slate-100">{hover.fullLabel}</p>
          <p className="mt-1 flex items-center gap-1.5 text-slate-400">
            <span className="h-2 w-2 rounded-full" style={{ background: hover.color }} />
            {hover.type === "project" ? "Project" : "Package"} - {STATUS_LABELS[hover.status] ?? hover.status}
          </p>
          {hover.score != null && (
            <p className="mt-0.5 text-slate-400">Highest V-RPS <span className="font-mono text-slate-200">{hover.score.toFixed(1)}</span> ({hover.priority})</p>
          )}
          {hover.advisories > 0 && <p className="mt-0.5 text-slate-400">{hover.advisories} advisor{hover.advisories === 1 ? "y" : "ies"}</p>}
          <p className="mt-1 text-[10px] text-slate-500">Click to trace its blast radius</p>
        </div>
      )}
    </div>
  );
}
