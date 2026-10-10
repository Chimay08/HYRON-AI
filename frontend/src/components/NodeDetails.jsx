import { Link } from "react-router-dom";
import { MousePointerClick } from "lucide-react";
import {
  Badge, EmptyState, EvidenceBadge, ExploitBadge, STATUS_COLORS, STATUS_LABELS, ScoreBadge, evidenceKind,
} from "./ui.jsx";

function Row({ label, children }) {
  return (
    <div className="flex justify-between gap-3 py-1.5 text-sm">
      <span className="text-slate-500">{label}</span>
      <span className="text-right text-slate-200">{children}</span>
    </div>
  );
}

export default function NodeDetails({ node, report, graph, onSelect }) {
  if (!node) {
    return (
      <EmptyState icon={MousePointerClick} title="Select a node">
        Click a package to see its advisories and everything that depends on it (its blast radius). Click a project to see its exposure.
      </EmptyState>
    );
  }
  const isProject = node.type === "project";
  const name = isProject ? node.id.replace(/^project:/, "") : null;
  const findings = report.findings.filter((f) => (isProject ? f.affected_projects.some((a) => a.project === name) : f.package_node === node.id));
  const dependsOn = graph.edges.filter((e) => e.source === node.id);
  const dependents = graph.edges.filter((e) => e.target === node.id);
  const labelOf = (id) => graph.nodes.find((n) => n.id === id)?.label ?? id;

  return (
    <div className="space-y-4 p-5">
      <div>
        <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500">{isProject ? "Project" : "Package"}</p>
        <p className="mt-1 break-all font-mono text-sm text-white">{node.label}</p>
        <p className="mt-1.5 flex items-center gap-2 text-xs text-slate-300">
          <span className="h-2.5 w-2.5 rounded-full" style={{ background: STATUS_COLORS[node.status] }} />{STATUS_LABELS[node.status]}
        </p>
      </div>
      <div className="divide-y divide-slate-800 border-y border-slate-800">
        <Row label="Ecosystem">{node.ecosystem ?? "-"}</Row>
        {!isProject && <Row label="Version">{node.version ?? "unresolved"}{node.version_status === "range_min" && <Badge tone="amber" className="ml-1">min of range</Badge>}</Row>}
        {!isProject && <Row label="Depth">{node.depth === 1 ? "direct" : node.depth ? `transitive (level ${node.depth})` : "-"}</Row>}
        {node.max_risk_score != null && <Row label="Highest V-RPS"><ScoreBadge score={node.max_risk_score} priority={node.priority ?? "low"} /></Row>}
        <Row label="Depends on">{dependsOn.length}</Row>
        <Row label="Dependents">{dependents.length}</Row>
      </div>

      {findings.length > 0 && (
        <div className="space-y-2">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">{isProject ? "Exposed to" : "Advisories"}</p>
          {findings.slice(0, 12).map((f) => {
            const ap = isProject ? f.affected_projects.find((a) => a.project === name) : null;
            const risk = ap ? ap.risk : f.max_risk;
            return (
              <div key={f.finding_id} className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <Link to={`/findings?q=${encodeURIComponent(f.vulnerability.id)}`} className="font-mono text-slate-100 hover:text-teal-300">{f.vulnerability.id}</Link>
                  <ScoreBadge score={risk.score} priority={risk.priority} provisional={risk.provisional} urgent={risk.urgent_review} />
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1"><EvidenceBadge kind={evidenceKind(f.vulnerability)} /><ExploitBadge vuln={f.vulnerability} /></div>
                {ap ? (
                  <p className="mt-1.5 break-all font-mono text-[11px] text-slate-400">{ap.relation}: {ap.path.join(" > ")}</p>
                ) : (
                  <p className="mt-1.5 text-slate-400">{f.vulnerability.summary}</p>
                )}
                {isProject && <button className="mt-1.5 text-teal-300 hover:underline" onClick={() => onSelect(f.package_node)}>Trace {f.package}</button>}
              </div>
            );
          })}
        </div>
      )}

      {dependents.length > 0 && (
        <div>
          <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Used by</p>
          <ul className="space-y-0.5">
            {dependents.slice(0, 20).map((e) => (
              <li key={e.source} className="flex items-center gap-1.5">
                <button className="truncate text-left font-mono text-xs text-slate-300 hover:text-teal-300" onClick={() => onSelect(e.source)}>{labelOf(e.source)}</button>
                {e.scope === "development" && <Badge>dev</Badge>}
                {e.inferred && <Badge tone="violet">inferred</Badge>}
              </li>
            ))}
          </ul>
        </div>
      )}
      {dependsOn.length > 0 && (
        <div>
          <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Depends on</p>
          <ul className="space-y-0.5">
            {dependsOn.slice(0, 20).map((e) => (
              <li key={e.target}><button className="truncate text-left font-mono text-xs text-slate-300 hover:text-teal-300" onClick={() => onSelect(e.target)}>{labelOf(e.target)}</button></li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
