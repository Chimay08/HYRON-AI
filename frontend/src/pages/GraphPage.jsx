import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Info, Network } from "lucide-react";
import { errorMessage } from "../api.js";
import { useApp, useReport } from "../context/AppContext.jsx";
import DependencyGraph from "../components/DependencyGraph.jsx";
import NodeDetails from "../components/NodeDetails.jsx";
import ScanBanner from "../components/ScanBanner.jsx";
import {
  Button, EmptyState, ErrorBox, Loading, Notice, PageIntro, Panel, STATUS_COLORS, STATUS_LABELS, ScanPicker,
  SEVERITY_ORDER, cn,
} from "../components/ui.jsx";

const selectClass = "h-9 rounded-lg border border-slate-700 bg-slate-950 px-2 text-sm text-slate-200 focus:border-teal-500 focus:outline-none";

export default function GraphPage() {
  const navigate = useNavigate();
  const { loadGraph } = useApp();
  const { id, report, loading, error } = useReport();
  const [graph, setGraph] = useState(null);
  const [graphState, setGraphState] = useState({ loading: false, error: "" });
  const [selectedId, setSelectedId] = useState(null);
  const [statuses, setStatuses] = useState(new Set(["vulnerable", "affected", "clean", "unscanned"]));
  const [ecosystem, setEcosystem] = useState("all");
  const [severity, setSeverity] = useState("all");

  useEffect(() => {
    if (!id) return;
    let alive = true;
    setGraph(null);
    setSelectedId(null);
    setGraphState({ loading: true, error: "" });
    loadGraph(id)
      .then((g) => {
        if (!alive) return;
        setGraph(g);
        setGraphState({ loading: false, error: "" });
        setSelectedId(g.nodes.find((n) => n.status === "vulnerable")?.id ?? null);
      })
      .catch((e) => alive && setGraphState({ loading: false, error: errorMessage(e) }));
    return () => {
      alive = false;
    };
  }, [id, loadGraph]);

  const filters = useMemo(() => ({ statuses, ecosystem, severity }), [statuses, ecosystem, severity]);
  const ecosystems = useMemo(() => [...new Set((graph?.nodes ?? []).map((n) => n.ecosystem).filter(Boolean))], [graph]);
  const selected = graph?.nodes.find((n) => n.id === selectedId) ?? null;
  const toggle = (s) => {
    const next = new Set(statuses);
    if (next.has(s)) next.delete(s);
    else next.add(s);
    setStatuses(next);
  };

  return (
    <>
      <PageIntro
        title="Dependency graph"
        description="Projects (rectangles) and packages (circles). Select a vulnerable package to trace its blast radius: every project that reaches it directly or transitively."
        actions={<ScanPicker />}
      />
      {!id && <Panel><EmptyState icon={Network} title="No scan selected" action={<Button variant="primary" onClick={() => navigate("/scan/new")}>New Scan</Button>}>Run a scan to build a dependency graph.</EmptyState></Panel>}
      {(loading || graphState.loading) && <Loading label="Building graph..." />}
      {(error || graphState.error) && <ErrorBox>{error || graphState.error}</ErrorBox>}

      {report && graph && (
        <div className="space-y-5">
          <ScanBanner report={report} />
          <Notice tone={graph.complete ? "teal" : "amber"} icon={Info}>
            <strong>{graph.complete ? "Complete graph. " : "Incomplete graph. "}</strong>{graph.completeness_note} Edges are only drawn where the input states a dependency.
          </Notice>

          <div className="flex flex-wrap items-center gap-2">
            {Object.entries(STATUS_LABELS).map(([key, label]) => (
              <button
                key={key} onClick={() => toggle(key)} aria-pressed={statuses.has(key)}
                className={cn("flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs transition-colors",
                  statuses.has(key) ? "border-slate-600 bg-slate-800 text-slate-100" : "border-slate-800 text-slate-500")}
              >
                <span className="h-2 w-2 rounded-full" style={{ background: STATUS_COLORS[key], opacity: statuses.has(key) ? 1 : 0.35 }} />{label}
              </button>
            ))}
            <select className={selectClass} value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity filter">
              <option value="all">All severities</option>
              {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s} paths</option>)}
            </select>
            <select className={selectClass} value={ecosystem} onChange={(e) => setEcosystem(e.target.value)} aria-label="Ecosystem filter">
              <option value="all">All ecosystems</option>
              {ecosystems.map((e) => <option key={e} value={e}>{e}</option>)}
            </select>
          </div>

          <div className="grid gap-5 xl:grid-cols-[1fr_340px]">
            <Panel bodyClass="p-2" className="min-w-0">
              {graph.nodes.length === 0 ? (
                <EmptyState icon={Network} title="Empty graph">No dependencies were found in the input.</EmptyState>
              ) : (
                <DependencyGraph graph={graph} filters={filters} selectedId={selectedId} onSelect={setSelectedId} />
              )}
              <div className="flex flex-wrap gap-x-4 gap-y-1 px-3 py-2 text-[11px] text-slate-400">
                {Object.entries(STATUS_LABELS).map(([k, l]) => (
                  <span key={k} className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full" style={{ background: STATUS_COLORS[k] }} />{l}</span>
                ))}
                <span className="flex items-center gap-1.5"><span className="h-2.5 w-3.5 rounded-sm bg-slate-300" />Project</span>
                <span className="flex items-center gap-1.5"><span className="w-5 border-t border-dashed border-slate-400" />Dev-only edge</span>
                <span className="flex items-center gap-1.5"><span className="w-5 border-t-2 border-dotted border-violet-400" />Inferred link</span>
                <span className="flex items-center gap-1.5"><span className="w-5 border-t-2 border-red-400" />Path to selection</span>
              </div>
            </Panel>
            <Panel bodyClass="p-0" className="max-h-[680px] overflow-y-auto">
              <NodeDetails node={selected} report={report} graph={graph} onSelect={setSelectedId} />
            </Panel>
          </div>
        </div>
      )}
    </>
  );
}
