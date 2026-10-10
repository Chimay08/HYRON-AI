import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Download, FileText, Printer, RefreshCw } from "lucide-react";
import { api } from "../api.js";
import { useApp, useReport } from "../context/AppContext.jsx";
import ScanBanner from "../components/ScanBanner.jsx";
import WebsiteResult from "../components/WebsiteResult.jsx";
import {
  Badge, Button, EmptyState, ErrorBox, EvidenceBadge, ExploitBadge, Loading, PageIntro, Panel, RemediationBadge,
  ScanStatusBadge, ScoreBadge, SEVERITY_COLORS, SEVERITY_ORDER, SeverityBadge, evidenceKind, formatDate,
} from "../components/ui.jsx";

function download(name, obj) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function Meta({ label, children }) {
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wider text-slate-500">{label}</dt>
      <dd className="mt-0.5 break-all text-sm text-slate-200">{children}</dd>
    </div>
  );
}

const SOURCE_TONE = { ok: "green", partial: "amber", stale: "amber", unavailable: "red", synthetic: "violet", not_used: "slate" };

function SeverityBar({ counts }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (!total) return <p className="text-sm text-slate-500">No findings.</p>;
  return (
    <div>
      <div className="flex h-2.5 overflow-hidden rounded-full bg-slate-800">
        {SEVERITY_ORDER.filter((s) => counts[s]).map((s) => (
          <div key={s} style={{ width: `${(counts[s] / total) * 100}%`, background: SEVERITY_COLORS[s] }} title={`${s}: ${counts[s]}`} />
        ))}
      </div>
      <div className="mt-2 flex flex-wrap gap-3 text-xs text-slate-400">
        {SEVERITY_ORDER.filter((s) => counts[s]).map((s) => (
          <span key={s} className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm" style={{ background: SEVERITY_COLORS[s] }} />{s} {counts[s]}</span>
        ))}
      </div>
    </div>
  );
}

function DependencyReport({ report, remediationOnly }) {
  const navigate = useNavigate();
  const { runScan, setCurrentScanId, currentScanId } = useApp();
  const [rescanError, setRescanError] = useState("");
  const s = report.summary;
  const projects = useMemo(() => {
    const map = new Map();
    report.findings.forEach((f) => f.affected_projects.forEach((a) => {
      const cur = map.get(a.project) ?? { project: a.project, findings: 0, max: 0, prio: "low", direct: 0, transitive: 0 };
      cur.findings += 1;
      if (a.risk.score > cur.max) { cur.max = a.risk.score; cur.prio = a.risk.priority; }
      cur[a.relation] += 1;
      map.set(a.project, cur);
    }));
    return [...map.values()].sort((a, b) => b.max - a.max);
  }, [report]);
  const paths = useMemo(() => report.findings.flatMap((f) => f.affected_projects.map((a) => ({ f, a }))).slice(0, 25), [report]);

  async function rescan() {
    setRescanError("");
    try {
      const r = await runScan(report.source.label, () => api.scanRepo(report.source.url, report.source.branch));
      navigate(`/reports/${r.scan_id}`);
    } catch (e) {
      setRescanError(e.message);
    }
  }

  return (
    <div className="print-report space-y-5">
      <PageIntro
        title={remediationOnly ? "Remediation report" : "Security report"}
        description={`${report.source.label}${report.source.branch ? ` @ ${report.source.branch}` : ""} - generated ${formatDate(report.created_at)}`}
        actions={
          <div className="flex flex-wrap gap-2 print:hidden">
            {currentScanId !== report.scan_id && <Button onClick={() => setCurrentScanId(report.scan_id)}>Set as current scan</Button>}
            {report.source.type === "repository" && <Button onClick={rescan}><RefreshCw className="h-4 w-4" />Re-scan</Button>}
            <Button onClick={() => download(`hyron-report-${report.scan_id}.json`, report)}><Download className="h-4 w-4" />Export JSON</Button>
            <Button variant="primary" onClick={() => window.print()}><Printer className="h-4 w-4" />Print / Save PDF</Button>
          </div>
        }
      />
      {rescanError && <ErrorBox title="Re-scan failed">{rescanError}</ErrorBox>}
      <ScanBanner report={report} compact />

      <Panel title="Scan metadata">
        <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Meta label="Scan ID"><span className="font-mono">{report.scan_id}</span></Meta>
          <Meta label="Status"><ScanStatusBadge status={report.status} /></Meta>
          <Meta label="Mode">{report.mode === "demo" ? <Badge tone="violet">Demo - simulated</Badge> : "Live"}</Meta>
          <Meta label="Source">{report.source.type}{report.source.url && <> - <a className="text-teal-300 hover:underline" href={report.source.url} target="_blank" rel="noreferrer noopener">{report.source.label}</a></>}</Meta>
          {report.source.commit && <Meta label="Commit"><span className="font-mono">{report.source.commit}</span></Meta>}
          <Meta label="Files">{report.source.files.slice(0, 6).join(", ")}{report.source.files.length > 6 ? "..." : ""}</Meta>
          <Meta label="Projects">{report.projects.length}</Meta>
          <Meta label="Packages analysed">{s.total_packages} ({s.direct_packages} direct, {s.transitive_packages} transitive) - {s.unscanned_packages} not scanned</Meta>
        </dl>
      </Panel>

      {!remediationOnly && (
        <>
          <div className="grid gap-5 lg:grid-cols-2">
            <Panel title="Executive summary">
              <p className="text-sm text-slate-300">
                {report.status === "verification_failed"
                  ? "The live vulnerability check failed; no findings in this report are verified."
                  : `${s.vulnerable_packages} vulnerable package version(s) with ${s.total_findings} advisory match(es) potentially affect ${s.affected_projects} of ${s.total_projects} project(s). ${s.high_priority_findings} finding(s) are high or critical priority by V-RPS.`}
              </p>
              <div className="mt-4"><SeverityBar counts={s.severity_counts} /></div>
            </Panel>
            <Panel title="Data sources" bodyClass="p-0">
              <table className="w-full text-left text-xs">
                <tbody className="divide-y divide-slate-800">
                  {report.data_sources.map((d) => (
                    <tr key={d.name}>
                      <td className="px-5 py-2.5 font-medium text-slate-200">{d.url ? <a href={d.url} target="_blank" rel="noreferrer noopener" className="hover:underline">{d.name}</a> : d.name}</td>
                      <td className="py-2.5"><Badge tone={SOURCE_TONE[d.status]}>{d.status}</Badge></td>
                      <td className="py-2.5 pr-5 text-slate-400">{d.detail}{d.retrieved_at && <span className="block text-slate-500">retrieved {formatDate(d.retrieved_at)}</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          </div>

          <Panel title="Vulnerability findings" description="Risk-ranked. Evidence labels distinguish confirmed advisory matches from OSV-reported and simulated results." bodyClass="p-0">
            {report.findings.length === 0 ? <EmptyState title="No findings" /> : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[820px] text-left text-xs">
                  <thead className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-500">
                    <tr><th className="px-5 py-2">#</th><th className="py-2">Package</th><th className="py-2">Advisory</th><th className="py-2">Evidence</th><th className="py-2">Severity</th><th className="py-2">Exploitation</th><th className="py-2">Fixed in</th><th className="py-2 pr-5">HYRON Risk</th></tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {report.findings.slice(0, 100).map((f, i) => (
                      <tr key={f.finding_id}>
                        <td className="px-5 py-2 text-slate-500">{i + 1}</td>
                        <td className="py-2 font-mono text-slate-200">{f.package}@{f.version}</td>
                        <td className="py-2 font-mono text-slate-300">{f.vulnerability.id}</td>
                        <td className="py-2"><EvidenceBadge kind={evidenceKind(f.vulnerability)} /></td>
                        <td className="py-2"><SeverityBadge label={f.vulnerability.severity_label} score={f.vulnerability.cvss_score} /></td>
                        <td className="py-2"><ExploitBadge vuln={f.vulnerability} /></td>
                        <td className="py-2 font-mono text-slate-300">{f.vulnerability.fixed_version ?? "-"}</td>
                        <td className="py-2 pr-5"><ScoreBadge score={f.max_risk.score} priority={f.max_risk.priority} provisional={f.max_risk.provisional} urgent={f.max_risk.urgent_review} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {report.findings.length > 100 && <p className="px-5 py-2 text-xs text-slate-500">First 100 of {report.findings.length} shown - the JSON export contains all findings.</p>}
              </div>
            )}
          </Panel>

          <div className="grid gap-5 lg:grid-cols-2">
            <Panel title="Potentially affected projects" description="Reachable in the dependency graph - exploitability not established" bodyClass="p-0">
              {projects.length === 0 ? <EmptyState title="None" /> : (
                <ul className="divide-y divide-slate-800">
                  {projects.map((p) => (
                    <li key={p.project} className="flex items-center justify-between gap-3 px-5 py-2.5 text-sm">
                      <span className="text-slate-200">{p.project}<span className="ml-2 text-xs text-slate-500">{p.findings} finding(s) - {p.direct} direct, {p.transitive} transitive</span></span>
                      <ScoreBadge score={p.max} priority={p.prio} />
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
            <Panel title="Dependency paths" description={`Shortest path from each project to each vulnerable package (first ${paths.length})`} bodyClass="p-0">
              {paths.length === 0 ? <EmptyState title="None" /> : (
                <ul className="divide-y divide-slate-800">
                  {paths.map(({ f, a }) => (
                    <li key={`${f.finding_id}-${a.project}`} className="px-5 py-2 font-mono text-[11px] text-slate-400">
                      <Badge tone={a.relation === "direct" ? "orange" : "slate"} className="mr-2">{a.relation}</Badge>{a.path.join(" > ")}
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
          </div>
        </>
      )}

      <Panel title={remediationOnly ? "Remediation steps" : "Risk ranking & recommended fixes"} bodyClass="p-0">
        {report.patch_plan.length === 0 ? <EmptyState title="No remediation steps" /> : (
          <ol className="divide-y divide-slate-800">
            {report.patch_plan.map((st) => (
              <li key={st.step_key} className="px-5 py-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="font-mono text-sm text-slate-100">{st.order}. {st.package} {st.current_version} -&gt; {st.recommended_version ?? "no verified fix"}</p>
                  <div className="flex gap-1.5"><ScoreBadge score={st.max_risk_score} priority={st.priority} urgent={st.urgent_review} /><RemediationBadge status={st.remediation_status} /></div>
                </div>
                <p className="mt-1 text-xs text-slate-400">{st.rationale}</p>
                {st.warnings.map((w) => <p key={w} className="mt-1 text-xs text-amber-300/90">! {w}</p>)}
                {remediationOnly && (
                  <div className="mt-2 grid gap-3 text-xs md:grid-cols-2">
                    <div>
                      <p className="font-medium text-slate-300">Actions</p>
                      <ul className="mt-1 list-disc space-y-0.5 pl-4 text-slate-400">{st.actions.map((a) => <li key={a}>{a}</li>)}</ul>
                      {st.upgrade_commands.length > 0 && <pre className="mt-2 whitespace-pre-wrap rounded bg-slate-950 p-2 font-mono text-teal-200">{st.upgrade_commands.join("\n")}</pre>}
                    </div>
                    <div>
                      <p className="font-medium text-slate-300">Checklist</p>
                      <ul className="mt-1 space-y-0.5 text-slate-400">{st.checklist.map((c) => <li key={c}>[ ] {c}</li>)}</ul>
                    </div>
                  </div>
                )}
              </li>
            ))}
          </ol>
        )}
      </Panel>

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel id="coverage" title="Incomplete-analysis warnings & coverage gaps">
          {report.warnings.length === 0 && report.coverage_gaps.length === 0 ? (
            <p className="text-sm text-slate-400">No coverage gaps were recorded.</p>
          ) : (
            <div className="space-y-3 text-sm">
              {report.warnings.length > 0 && <ul className="list-disc space-y-1 pl-5 text-slate-300">{report.warnings.map((w) => <li key={w}>{w}</li>)}</ul>}
              {report.coverage_gaps.length > 0 && (
                <div>
                  <p className="font-medium text-slate-200">Not scanned - exposure unknown (not confirmed safe)</p>
                  <ul className="mt-1 space-y-0.5 text-xs text-slate-400">
                    {report.coverage_gaps.slice(0, 40).map((g) => <li key={`${g.package}-${g.declared}`}><span className="font-mono text-slate-300">{g.package}</span> {g.declared ? `(${g.declared})` : ""} - {g.reason}</li>)}
                  </ul>
                </div>
              )}
            </div>
          )}
          {report.parse_issues.length > 0 && (
            <details className="mt-3 text-xs text-slate-400">
              <summary className="cursor-pointer text-slate-300">Parser notes ({report.parse_issues.length})</summary>
              <ul className="mt-2 space-y-0.5">{report.parse_issues.map((p, i) => <li key={i}><span className="font-mono">{p.file}</span>: {p.message}</li>)}</ul>
            </details>
          )}
        </Panel>
        <Panel title="Limitations">
          <ul className="list-disc space-y-1 pl-5 text-sm text-slate-400">{report.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
        </Panel>
      </div>
      <p className="text-xs text-slate-500">
        V-RPS = 0.35S + 0.30E + 0.20X + 0.15P - a project-specific remediation-priority heuristic, not an industry standard.
        Generated by HYRON AI {formatDate(report.created_at)}.
      </p>
    </div>
  );
}

export default function Report() {
  const { scanId } = useParams();
  const [params] = useSearchParams();
  const { report, loading, error } = useReport(scanId);
  const remediationOnly = params.get("view") === "remediation";

  useEffect(() => {
    if (report) document.title = `HYRON AI - ${remediationOnly ? "Remediation report" : "Report"} ${report.scan_id}`;
    return () => { document.title = "HYRON AI"; };
  }, [report, remediationOnly]);

  if (loading) return <Loading label="Loading report..." />;
  if (error) {
    return (
      <Panel>
        <EmptyState icon={FileText} title="Report unavailable" action={<Link className="text-sm text-teal-300 hover:underline" to="/history">Go to scan history</Link>}>
          {error}
        </EmptyState>
      </Panel>
    );
  }
  if (!report) return null;
  if (report.kind === "website") {
    return (
      <div className="print-report">
        <PageIntro title="Website inspection" description="Passive technology inspection of a public page"
          actions={<div className="flex gap-2 print:hidden">
            <Button onClick={() => download(`hyron-website-${report.scan_id}.json`, report)}><Download className="h-4 w-4" />Export JSON</Button>
            <Button variant="primary" onClick={() => window.print()}><Printer className="h-4 w-4" />Print / Save PDF</Button>
          </div>} />
        <WebsiteResult report={report} />
      </div>
    );
  }
  return <DependencyReport report={report} remediationOnly={remediationOnly} />;
}

