import { Fragment, useState } from "react";
import { Bot, ChevronDown, ChevronRight, ExternalLink } from "lucide-react";
import {
  Badge, Button, EvidenceBadge, ExploitBadge, ScoreBadge, SeverityBadge, cn, evidenceKind,
} from "./ui.jsx";

const EXPLOIT_TEXT = { cisa_kev: "Listed in CISA KEV (known exploited)", epss: "FIRST EPSS probability", unknown: "No evidence available" };

function Factor({ title, value, children }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
      <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500">{title}</p>
      <p className="mt-1 font-mono text-lg text-white">{value}</p>
      <div className="mt-1 text-xs text-slate-400">{children}</div>
    </div>
  );
}

function Evidence({ finding, onExplain }) {
  const v = finding.vulnerability;
  const r = finding.max_risk;
  const f = r.factors;
  const x = finding.exposure;
  return (
    <div className="space-y-4">
      <div className="grid gap-3 md:grid-cols-4">
        <Factor title="Severity" value={`CVSS ${f.cvss}`}>
          {f.cvss_source === "vector" ? "Computed from the advisory's CVSS v3 vector" :
            f.cvss_source === "severity_label" ? `Estimated from label "${v.severity_label}"` : "Not provided - placeholder used"}
          {v.cvss_vector && <p className="mt-1 break-all font-mono text-[10px] text-slate-500">{v.cvss_vector}</p>}
        </Factor>
        <Factor title="Exploitability" value={f.exploit_source === "epss" ? `${(f.exploit_signal * 100).toFixed(1)}%` : f.exploit_signal.toFixed(1)}>
          {EXPLOIT_TEXT[f.exploit_source]}
          {v.in_kev === null && <p className="mt-1 text-amber-300/80">KEV data unavailable for this scan</p>}
        </Factor>
        <Factor title="Exposure" value={`${f.exposure_score.toFixed(0)}/100`}>
          Highest-risk path: {f.runtime_context}. {x.production_projects} production, {x.development_only_projects} dev-only, {x.unknown_context_projects} unknown.
        </Factor>
        <Factor title="Propagation" value={`${f.propagation_score.toFixed(0)}/100`}>
          {x.affected_projects} distinct project(s): {x.direct_dependents} direct, {x.transitive_dependents} transitive.
        </Factor>
      </div>

      <div className="rounded-lg bg-slate-950 px-3 py-2 font-mono text-xs text-teal-200">
        V-RPS = 0.35({f.severity_score.toFixed(0)}) + 0.30({f.exploit_score.toFixed(0)}) + 0.20({f.exposure_score.toFixed(0)}) + 0.15({f.propagation_score.toFixed(0)}) = {r.score.toFixed(1)}
        <span className="ml-2 font-sans text-slate-500">(highest-risk project, {f.runtime_context} context)</span>
      </div>
      {r.notes.length > 0 && (
        <ul className="list-disc space-y-0.5 pl-5 text-xs text-amber-200/80">{r.notes.map((n) => <li key={n}>{n}</li>)}</ul>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">Advisory evidence</p>
          <dl className="space-y-1.5 text-xs">
            <div className="flex gap-2"><dt className="w-24 shrink-0 text-slate-500">Source</dt><dd className="text-slate-300">{v.source}</dd></div>
            <div className="flex gap-2"><dt className="w-24 shrink-0 text-slate-500">Match</dt><dd><EvidenceBadge kind={evidenceKind(v)} /></dd></div>
            {v.aliases.length > 0 && <div className="flex gap-2"><dt className="w-24 shrink-0 text-slate-500">Aliases</dt><dd className="break-all font-mono text-slate-300">{v.aliases.join(", ")}</dd></div>}
            <div className="flex gap-2"><dt className="w-24 shrink-0 text-slate-500">Fixed in</dt><dd className="font-mono text-slate-300">{v.fixed_version ?? "none published"}</dd></div>
            {(v.published || v.modified) && <div className="flex gap-2"><dt className="w-24 shrink-0 text-slate-500">Dates</dt><dd className="text-slate-300">published {v.published?.slice(0, 10) ?? "?"}, modified {v.modified?.slice(0, 10) ?? "?"}</dd></div>}
          </dl>
          <p className="mt-3 text-xs leading-relaxed text-slate-400">{finding.explanation}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {v.source_url && (
              <a href={v.source_url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-2.5 py-1.5 text-xs text-slate-200 hover:border-teal-500/60">
                <ExternalLink className="h-3.5 w-3.5" />View advisory
              </a>
            )}
            <Button size="sm" onClick={() => onExplain(finding)}><Bot className="h-3.5 w-3.5" />Ask Copilot</Button>
          </div>
        </div>
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">Potentially affected projects & paths</p>
          <ul className="space-y-1.5">
            {finding.affected_projects.map((a) => (
              <li key={a.project} className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium text-slate-200">{a.project}</span>
                  <ScoreBadge score={a.risk.score} priority={a.risk.priority} provisional={a.risk.provisional} urgent={a.risk.urgent_review} />
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-1.5 text-slate-500">
                  <Badge tone={a.relation === "direct" ? "orange" : "slate"}>{a.relation}</Badge>
                  <Badge tone={a.runtime_context === "development" ? "slate" : a.runtime_context === "production" ? "teal" : "amber"}>{a.runtime_context}</Badge>
                  {a.inferred_link && <Badge tone="amber">inferred link</Badge>}
                </div>
                <p className="mt-1 break-all font-mono text-[11px] text-slate-400">{a.path.join(" > ")}</p>
              </li>
            ))}
            {finding.affected_projects.length === 0 && <li className="text-xs text-slate-500">No scanned project depends on this package.</li>}
          </ul>
        </div>
      </div>
    </div>
  );
}

export default function RiskTable({ findings, onExplain, initiallyOpen }) {
  const [open, setOpen] = useState(initiallyOpen ?? null);
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[900px] text-left text-sm">
        <thead className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-500">
          <tr>
            <th className="py-2.5 pl-5 pr-3 font-medium">Package</th>
            <th className="py-2.5 pr-3 font-medium">Advisory</th>
            <th className="py-2.5 pr-3 font-medium">Severity</th>
            <th className="py-2.5 pr-3 font-medium">Exploitation</th>
            <th className="py-2.5 pr-3 font-medium">Exposure</th>
            <th className="py-2.5 pr-3 font-medium">Fixed in</th>
            <th className="py-2.5 pr-5 font-medium">HYRON Risk</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/80">
          {findings.map((f) => {
            const isOpen = open === f.finding_id;
            const v = f.vulnerability;
            return (
              <Fragment key={f.finding_id}>
                <tr
                  className={cn("cursor-pointer align-top transition-colors hover:bg-slate-800/30", isOpen && "bg-slate-800/30")}
                  onClick={() => setOpen(isOpen ? null : f.finding_id)}
                  aria-expanded={isOpen}
                >
                  <td className="py-3 pl-5 pr-3">
                    <div className="flex items-start gap-2">
                      {isOpen ? <ChevronDown className="mt-0.5 h-4 w-4 text-slate-500" /> : <ChevronRight className="mt-0.5 h-4 w-4 text-slate-500" />}
                      <div className="min-w-0">
                        <p className="font-mono text-slate-100">{f.package}</p>
                        <p className="font-mono text-xs text-slate-500">
                          {f.ecosystem} - {f.version}
                          {f.version_status === "range_min" && <span className="ml-1 text-amber-300" title="Lower bound of a declared range">(min)</span>}
                        </p>
                      </div>
                    </div>
                  </td>
                  <td className="py-3 pr-3">
                    <p className="font-mono text-xs text-slate-200">{v.id}</p>
                    <div className="mt-1 flex flex-wrap gap-1"><EvidenceBadge kind={evidenceKind(v)} /></div>
                  </td>
                  <td className="py-3 pr-3"><SeverityBadge label={v.severity_label} score={v.cvss_score} estimated={v.cvss_source === "severity_label"} /></td>
                  <td className="py-3 pr-3"><ExploitBadge vuln={v} /></td>
                  <td className="py-3 pr-3 text-xs text-slate-300">
                    {f.exposure.affected_projects} project(s)
                    <p className="text-slate-500">{f.exposure.direct_dependents} direct, {f.exposure.transitive_dependents} transitive</p>
                  </td>
                  <td className="py-3 pr-3 font-mono text-xs">{v.fixed_version ? <span className="text-emerald-300">{v.fixed_version}</span> : <span className="text-slate-500">none known</span>}</td>
                  <td className="py-3 pr-5"><ScoreBadge score={f.max_risk.score} priority={f.max_risk.priority} provisional={f.max_risk.provisional} urgent={f.max_risk.urgent_review} /></td>
                </tr>
                {isOpen && (
                  <tr className="bg-slate-900">
                    <td colSpan={7} className="px-5 py-5"><Evidence finding={f} onExplain={onExplain} /></td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
