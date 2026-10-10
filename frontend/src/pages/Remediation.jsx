import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { CheckCircle2, FileText, Wrench } from "lucide-react";
import { useApp, useReport } from "../context/AppContext.jsx";
import PatchPlan from "../components/PatchPlan.jsx";
import ScanBanner from "../components/ScanBanner.jsx";
import {
  Badge, Button, EmptyState, ErrorBox, Loading, Notice, PageIntro, Panel, ScanPicker, cn,
} from "../components/ui.jsx";

const FILTERS = [
  ["all", "All"], ["open", "Open"], ["under_review", "Under review"], ["resolved_reported", "User-reported"],
  ["still_detected", "Still detected"],
];

export default function Remediation() {
  const navigate = useNavigate();
  const { putReport } = useApp();
  const { id, report, loading, error } = useReport();
  const [filter, setFilter] = useState("all");

  const counts = useMemo(() => {
    const c = {};
    (report?.patch_plan ?? []).forEach((s) => { c[s.remediation_status] = (c[s.remediation_status] ?? 0) + 1; });
    return c;
  }, [report]);

  function onStepUpdated(step) {
    putReport({ ...report, patch_plan: report.patch_plan.map((s) => (s.step_key === step.step_key ? step : s)) });
  }

  const visible = report ? { ...report, patch_plan: report.patch_plan.filter((s) => filter === "all" || s.remediation_status === filter) } : null;

  return (
    <>
      <PageIntro
        title="Remediation center"
        description="Ordered by V-RPS, then production exposure. Fixed versions come from advisory data; compatibility is not verified and nothing is changed automatically."
        actions={
          <>
            <ScanPicker />
            {report && <Button onClick={() => navigate(`/reports/${report.scan_id}?view=remediation`)}><FileText className="h-4 w-4" />Generate remediation report</Button>}
          </>
        }
      />
      {!id && <Panel><EmptyState icon={Wrench} title="No scan selected" action={<Button variant="primary" onClick={() => navigate("/scan/new")}>New Scan</Button>}>Run a scan to get a remediation plan.</EmptyState></Panel>}
      {loading && <Loading />}
      {error && <ErrorBox>{error}</ErrorBox>}
      {report && (
        <div className="space-y-5">
          <ScanBanner report={report} />

          {report.resolved_since_previous.length > 0 && (
            <Notice tone="teal" icon={CheckCircle2}>
              <p className="font-medium">Verified by re-scan</p>
              <p className="mt-1">Compared with scan {report.previous_scan_id}, these are no longer detected:</p>
              <ul className="mt-1.5 flex flex-wrap gap-1.5">
                {report.resolved_since_previous.map((r) => <Badge key={r.step_key} tone="green">{r.package}@{r.version}</Badge>)}
              </ul>
            </Notice>
          )}

          <div className="flex flex-wrap gap-2" role="tablist">
            {FILTERS.map(([key, label]) => (
              <button key={key} role="tab" aria-selected={filter === key} onClick={() => setFilter(key)}
                className={cn("rounded-full border px-3 py-1 text-xs", filter === key ? "border-teal-500/60 bg-teal-500/10 text-teal-200" : "border-slate-800 text-slate-400 hover:text-slate-200")}>
                {label} <span className="ml-1 text-slate-500">{key === "all" ? report.patch_plan.length : counts[key] ?? 0}</span>
              </button>
            ))}
          </div>

          {report.patch_plan.length === 0 ? (
            <Panel><EmptyState icon={CheckCircle2} title="No remediation needed">
              {report.status === "verification_failed" ? "The live check failed, so nothing was verified. Retry the scan." : "No vulnerable package versions were found in this scan."}
            </EmptyState></Panel>
          ) : visible.patch_plan.length === 0 ? (
            <Panel><EmptyState title="No steps with this status" /></Panel>
          ) : (
            <PatchPlan report={visible} onStepUpdated={onStepUpdated} />
          )}
        </div>
      )}
    </>
  );
}
