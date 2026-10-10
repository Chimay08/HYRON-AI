import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Bot, Search, ShieldAlert } from "lucide-react";
import { useReport } from "../context/AppContext.jsx";
import RiskTable from "../components/RiskTable.jsx";
import Copilot from "../components/Copilot.jsx";
import ScanBanner from "../components/ScanBanner.jsx";
import {
  Button, EmptyState, ErrorBox, Loading, PageIntro, Panel, ScanPicker, SEVERITY_ORDER, inputClass,
} from "../components/ui.jsx";

const selectClass = "h-9 rounded-lg border border-slate-700 bg-slate-950 px-2 text-sm text-slate-200 focus:border-teal-500 focus:outline-none";

export default function Findings() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const { id, report, loading, error } = useReport();
  const [severity, setSeverity] = useState("all");
  const [priority, setPriority] = useState("all");
  const [ecosystem, setEcosystem] = useState("all");
  const [project, setProject] = useState("all");
  const [copilot, setCopilot] = useState({ open: false, finding: null });
  const q = params.get("q") ?? "";

  const findings = report?.findings ?? [];
  const ecosystems = useMemo(() => [...new Set(findings.map((f) => f.ecosystem))], [findings]);
  const projects = report?.projects ?? [];

  const filtered = useMemo(() => {
    const term = q.trim().toLowerCase();
    return findings.filter((f) =>
      (severity === "all" || (f.vulnerability.severity_label ?? "UNKNOWN") === severity) &&
      (priority === "all" || f.max_risk.priority === priority) &&
      (ecosystem === "all" || f.ecosystem === ecosystem) &&
      (project === "all" || f.affected_projects.some((a) => a.project === project)) &&
      (!term || [f.package, f.vulnerability.id, ...f.vulnerability.aliases, f.vulnerability.summary]
        .some((s) => s.toLowerCase().includes(term))));
  }, [findings, q, severity, priority, ecosystem, project]);

  const intro = (
    <PageIntro
      title="Vulnerability findings"
      description="Package versions matched to advisories, ranked by V-RPS. Severity, exploit evidence, exposure and propagation are shown separately."
      actions={
        <>
          <ScanPicker />
          {report && <Button onClick={() => setCopilot({ open: true, finding: null })}><Bot className="h-4 w-4" />Summarise scan</Button>}
        </>
      }
    />
  );

  if (!id) {
    return (
      <>
        {intro}
        <Panel><EmptyState icon={ShieldAlert} title="No scan selected" action={<Button variant="primary" onClick={() => navigate("/scan/new")}>New Scan</Button>}>Run a scan to see findings.</EmptyState></Panel>
      </>
    );
  }

  return (
    <>
      {intro}
      {loading && <Loading />}
      {error && <ErrorBox>{error}</ErrorBox>}
      {report && (
        <div className="space-y-5">
          <ScanBanner report={report} />
          <Panel bodyClass="p-0" title={`${filtered.length} of ${findings.length} findings`}
            actions={
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative">
                  <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
                  <input
                    value={q} onChange={(e) => setParams(e.target.value ? { q: e.target.value } : {})}
                    placeholder="Package, advisory, CVE" aria-label="Search findings"
                    className={`${inputClass} h-9 w-52 pl-8`}
                  />
                </div>
                <select className={selectClass} value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
                  <option value="all">All severities</option>
                  {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
                <select className={selectClass} value={priority} onChange={(e) => setPriority(e.target.value)} aria-label="Priority">
                  <option value="all">All priorities</option>
                  <option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
                </select>
                <select className={selectClass} value={ecosystem} onChange={(e) => setEcosystem(e.target.value)} aria-label="Ecosystem">
                  <option value="all">All ecosystems</option>
                  {ecosystems.map((e) => <option key={e} value={e}>{e}</option>)}
                </select>
                <select className={selectClass} value={project} onChange={(e) => setProject(e.target.value)} aria-label="Project">
                  <option value="all">All projects</option>
                  {projects.map((p) => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
            }>
            {findings.length === 0 ? (
              <EmptyState icon={ShieldAlert} title={report.status === "verification_failed" ? "No verified results" : "No known vulnerabilities matched"}>
                {report.status === "verification_failed"
                  ? "The live check failed - the absence of findings means nothing here. Retry the scan."
                  : "Not a guarantee of safety: advisories can be missing and unscanned packages are unknown."}
              </EmptyState>
            ) : filtered.length === 0 ? (
              <EmptyState title="No findings match the filters" />
            ) : (
              <RiskTable
                key={report.scan_id + q}
                findings={filtered}
                initiallyOpen={q && filtered.length === 1 ? filtered[0].finding_id : null}
                onExplain={(finding) => setCopilot({ open: true, finding })}
              />
            )}
          </Panel>
          <p className="text-xs text-slate-500">
            * severity estimated from a qualitative label. ~ provisional score (evidence missing). V-RPS is a project-specific remediation-priority heuristic, not an industry standard.
          </p>
        </div>
      )}
      <Copilot open={copilot.open} onClose={() => setCopilot({ open: false, finding: null })} scanId={id} finding={copilot.finding} />
    </>
  );
}
