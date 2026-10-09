import { Globe, Info } from "lucide-react";
import {
  Badge, EmptyState, EvidenceBadge, ExploitBadge, Notice, Panel, ScanStatusBadge, SeverityBadge, formatDate,
} from "./ui.jsx";

export default function WebsiteResult({ report }) {
  return (
    <div className="space-y-5">
      <Notice tone="slate" icon={Info}>
        <p className="font-medium text-slate-100">Passive inspection - not a dependency vulnerability scan</p>
        <p className="mt-1 text-slate-400">{report.notice}</p>
      </Notice>

      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Globe className="h-4 w-4 text-slate-500" />
        <a href={report.final_url} target="_blank" rel="noreferrer noopener" className="font-mono text-teal-300 hover:underline">{report.final_url}</a>
        <Badge>HTTP {report.http_status}</Badge>
        <ScanStatusBadge status={report.status} />
        <span className="text-xs text-slate-500">{formatDate(report.created_at)}</span>
      </div>
      {report.status !== "completed" && <Notice tone={report.status === "verification_failed" ? "red" : "amber"}>{report.status_detail}</Notice>}

      <div className="grid gap-5 lg:grid-cols-3">
        <Panel title="Technology detected" description="Observed in headers or markup" actions={<EvidenceBadge kind="technology" />} bodyClass="p-0">
          {report.technologies.length === 0 ? (
            <EmptyState title="No technologies identified">The page exposes no recognisable headers or library markers.</EmptyState>
          ) : (
            <ul className="divide-y divide-slate-800">
              {report.technologies.map((t) => (
                <li key={`${t.name}-${t.version}`} className="px-5 py-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm text-slate-100">{t.name}{t.version && <span className="ml-1.5 font-mono text-slate-400">{t.version}</span>}</span>
                    <Badge tone={t.confidence === "high" ? "teal" : t.confidence === "medium" ? "sky" : "slate"}>{t.confidence}</Badge>
                  </div>
                  <p className="mt-0.5 text-xs text-slate-500">{t.category}</p>
                  <p className="mt-1 break-all font-mono text-[11px] text-slate-500">{t.evidence}</p>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel className="lg:col-span-2" title="Potential exposure" description="Library versions seen in public asset URLs that match OSV advisories - unconfirmed" actions={<EvidenceBadge kind="potential" />} bodyClass="p-0">
          {report.potential_exposures.length === 0 ? (
            <EmptyState title="No potential exposures">
              No versioned frontend libraries matched OSV advisories. This does not mean the site is secure - backend dependencies are not observable.
            </EmptyState>
          ) : (
            <ul className="divide-y divide-slate-800">
              {report.potential_exposures.map((e) => (
                <li key={`${e.npm_package}-${e.vulnerability.id}`} className="px-5 py-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono text-sm text-slate-100">{e.npm_package}@{e.version}</span>
                    <div className="flex items-center gap-1.5">
                      <SeverityBadge label={e.vulnerability.severity_label} score={e.vulnerability.cvss_score} />
                      <ExploitBadge vuln={e.vulnerability} />
                    </div>
                  </div>
                  <p className="mt-1 text-xs text-slate-400">
                    <a className="font-mono text-teal-300 hover:underline" href={e.vulnerability.source_url} target="_blank" rel="noreferrer noopener">{e.vulnerability.id}</a>
                    {" - "}{e.vulnerability.summary}
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    {e.vulnerability.fixed_version ? `Fixed in ${e.vulnerability.fixed_version}` : "No fixed version published"} - evidence: {e.evidence}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <Panel title="Confirmed package vulnerability" actions={<EvidenceBadge kind="confirmed" />}>
        <p className="text-sm text-slate-400">
          None - a website inspection cannot confirm package vulnerabilities. Scan the site's repository or its lockfiles to confirm.
        </p>
      </Panel>

      <Panel title="Limitations">
        <ul className="list-disc space-y-1 pl-5 text-sm text-slate-400">{report.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
      </Panel>
    </div>
  );
}
