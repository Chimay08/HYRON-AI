import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { ClipboardCheck, ExternalLink, GitPullRequest, Terminal, TriangleAlert } from "lucide-react";
import { api, errorMessage } from "../api.js";
import {
  Badge, Button, CopyButton, ErrorBox, Field, Loading, Modal, RemediationBadge, ScoreBadge, SeverityBadge,
  SEVERITY_ORDER, SimulatedBadge, cn, inputClass,
} from "./ui.jsx";

const FIX_STATUS = {
  fix_available: ["green", "Fix listed in advisory"],
  needs_review: ["amber", "Fix needs review"],
  no_fix_known: ["red", "No fix known"],
};

function worstSeverity(findings) {
  const labels = findings.map((f) => f.vulnerability.severity_label ?? "UNKNOWN");
  return SEVERITY_ORDER.find((s) => labels.includes(s)) ?? "UNKNOWN";
}

function ResolveModal({ open, onClose, onConfirm, step, busy }) {
  const [checked, setChecked] = useState(false);
  const [note, setNote] = useState("");
  return (
    <Modal open={open} onClose={onClose} title={`Mark ${step.package} as resolved`}
      footer={<>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" disabled={!checked} loading={busy} onClick={() => onConfirm(note)}>Mark resolved</Button>
      </>}>
      <p>This records a <strong className="text-white">user-reported</strong> resolution. It is not verification: the step only becomes
        <em> verified</em> when a re-scan of the same source no longer detects {step.package}@{step.current_version}.</p>
      <div className="mt-4 space-y-3">
        <Field label="Note (optional)"><input className={inputClass} value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} placeholder="e.g. upgraded in PR #123" /></Field>
        <label className="flex items-start gap-2 text-sm text-slate-200">
          <input type="checkbox" checked={checked} onChange={(e) => setChecked(e.target.checked)} className="mt-1 accent-teal-500" />
          I confirm the fix has been applied and tested.
        </label>
      </div>
    </Modal>
  );
}

function PRModal({ open, onClose, scanId, step }) {
  const [state, setState] = useState({ status: "idle" });
  useEffect(() => {
    if (!open) return undefined;
    let alive = true;
    setState({ status: "loading" });
    api.prDraft(scanId, step.step_key)
      .then((data) => alive && setState({ status: "done", data }))
      .catch((e) => alive && setState({ status: "error", error: errorMessage(e) }));
    return () => {
      alive = false;
    };
  }, [open, scanId, step.step_key]);
  const d = state.data;
  return (
    <Modal open={open} onClose={onClose} title="Proposed pull request" wide
      footer={d && <>
        <CopyButton text={d.body} label="Copy description" />
        {d.compare_url && <a href={d.compare_url} target="_blank" rel="noreferrer noopener" className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-slate-700 px-2.5 text-xs text-slate-200 hover:border-teal-500/60"><ExternalLink className="h-3.5 w-3.5" />Open compare view</a>}
      </>}>
      {state.status === "loading" && <Loading />}
      {state.status === "error" && <ErrorBox>{state.error}</ErrorBox>}
      {d && (
        <div className="space-y-3">
          <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-100">{d.note} HYRON AI never pushes, merges or deploys.</p>
          <div><p className="text-xs text-slate-500">Title</p><p className="flex items-center justify-between gap-2 font-mono text-sm text-white">{d.title}<CopyButton text={d.title} /></p></div>
          <div><p className="text-xs text-slate-500">Branch</p><p className="flex items-center justify-between gap-2 font-mono text-sm text-slate-200">{d.branch}<CopyButton text={`git checkout -b ${d.branch}`} label="Copy git command" /></p></div>
          <div><p className="mb-1 text-xs text-slate-500">Description (Markdown)</p><pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded-lg bg-slate-950 p-3 font-mono text-xs text-slate-300">{d.body}</pre></div>
        </div>
      )}
    </Modal>
  );
}

export function StepCard({ step, findings, scanId, simulated, onStatus }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [resolveOpen, setResolveOpen] = useState(false);
  const [prOpen, setPrOpen] = useState(false);
  const [checks, setChecks] = useState({});
  const mine = findings.filter((f) => f.package_node === step.step_key);
  const [fixTone, fixText] = FIX_STATUS[step.fix_status];

  async function setStatus(status, confirm = false, note = "") {
    setBusy(true);
    setError("");
    try {
      onStatus(await api.setStatus(scanId, step.step_key, status, confirm, note));
      setResolveOpen(false);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <motion.li layout className="rounded-xl border border-slate-800 bg-slate-900/60">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800 px-5 py-4">
        <div className="flex min-w-0 items-start gap-3">
          <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-teal-500/15 text-sm font-semibold text-teal-300">{step.order}</span>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-white">
              {mine[0]?.vulnerability.summary ? mine[0].vulnerability.summary.slice(0, 110) : `Vulnerable ${step.package}`}
            </p>
            <p className="mt-1 font-mono text-xs text-slate-400">
              {step.package} <span className="text-red-300">{step.current_version}</span> <span className="text-slate-600">-&gt;</span>{" "}
              {step.recommended_version ? <span className="text-emerald-300">{step.recommended_version}</span> : <span className="text-slate-500">no verified fix</span>}
            </p>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {simulated && <SimulatedBadge />}
              <SeverityBadge label={worstSeverity(mine)} />
              <ScoreBadge score={step.max_risk_score} priority={step.priority} urgent={step.urgent_review} />
              <Badge tone={fixTone}>{fixText}</Badge>
              <RemediationBadge status={step.remediation_status} />
            </div>
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5 print:hidden">
          {step.remediation_status !== "under_review" && step.remediation_status !== "resolved_reported" && (
            <Button size="sm" onClick={() => setStatus("under_review")} loading={busy}>Mark under review</Button>
          )}
          {step.remediation_status !== "resolved_reported" && <Button size="sm" onClick={() => setResolveOpen(true)}>Mark resolved</Button>}
          {step.remediation_status !== "open" && <Button size="sm" variant="ghost" onClick={() => setStatus("open")}>Reopen</Button>}
          <Button size="sm" disabled={!step.recommended_version} onClick={() => setPrOpen(true)}><GitPullRequest className="h-3.5 w-3.5" />Prepare PR</Button>
        </div>
      </div>

      <div className="grid gap-5 px-5 py-4 lg:grid-cols-2">
        <div className="space-y-4">
          <p className="text-sm text-slate-300">{step.rationale}</p>
          {step.status_note && <p className="text-xs text-slate-400">Status: {step.status_note}</p>}
          {step.warnings.length > 0 && (
            <ul className="space-y-1.5">
              {step.warnings.map((w) => (
                <li key={w} className="flex gap-2 rounded-lg bg-amber-500/10 px-3 py-2 text-xs text-amber-100"><TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />{w}</li>
              ))}
            </ul>
          )}
          <div>
            <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Advisory evidence</p>
            <ul className="space-y-1">
              {mine.slice(0, 8).map((f) => (
                <li key={f.finding_id} className="flex flex-wrap items-center gap-2 text-xs">
                  {f.vulnerability.source_url ? (
                    <a href={f.vulnerability.source_url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 font-mono text-teal-300 hover:underline">{f.vulnerability.id}<ExternalLink className="h-3 w-3" /></a>
                  ) : <span className="font-mono text-slate-300">{f.vulnerability.id}</span>}
                  <span className="text-slate-500">fixed in {f.vulnerability.fixed_version ?? "-"}</span>
                </li>
              ))}
              {mine.length > 8 && <li className="text-xs text-slate-500">and {mine.length - 8} more</li>}
            </ul>
          </div>
          <div>
            <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Affected applications</p>
            <ul className="space-y-1 text-xs text-slate-300">{step.actions.map((a) => <li key={a} className="rounded-md bg-slate-950/60 px-2.5 py-1.5">{a}</li>)}</ul>
          </div>
        </div>
        <div className="space-y-4">
          {step.upgrade_commands.length > 0 && (
            <div>
              <p className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400"><Terminal className="h-3.5 w-3.5" />Suggested commands</p>
              <ul className="space-y-1">
                {step.upgrade_commands.map((c) => (
                  <li key={c} className="flex items-center justify-between gap-2 rounded-lg bg-slate-950 px-3 py-1.5">
                    <code className="break-all font-mono text-xs text-teal-200">{c}</code>
                    <span className="print:hidden"><CopyButton text={c} /></span>
                  </li>
                ))}
              </ul>
              <p className="mt-1 text-[11px] text-slate-500">Review before running. Commands assume the project's root directory.</p>
            </div>
          )}
          <div>
            <p className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400"><ClipboardCheck className="h-3.5 w-3.5" />Compatibility & regression checklist</p>
            <ul className="space-y-1.5">
              {step.checklist.map((c, i) => (
                <li key={c}>
                  <label className="flex items-start gap-2 text-xs text-slate-300">
                    <input type="checkbox" checked={!!checks[i]} onChange={(e) => setChecks({ ...checks, [i]: e.target.checked })} className="mt-0.5 accent-teal-500" />
                    <span className={cn(checks[i] && "text-slate-500 line-through")}>{c}</span>
                  </label>
                </li>
              ))}
            </ul>
          </div>
          {error && <ErrorBox>{error}</ErrorBox>}
        </div>
      </div>
      <ResolveModal open={resolveOpen} onClose={() => setResolveOpen(false)} step={step} busy={busy}
        onConfirm={(note) => setStatus("resolved_reported", true, note)} />
      <PRModal open={prOpen} onClose={() => setPrOpen(false)} scanId={scanId} step={step} />
    </motion.li>
  );
}

export default function PatchPlan({ report, onStepUpdated }) {
  return (
    <ol className="space-y-4">
      {report.patch_plan.map((step) => (
        <StepCard key={step.step_key} step={step} findings={report.findings} scanId={report.scan_id}
          simulated={report.mode === "demo"} onStatus={onStepUpdated} />
      ))}
    </ol>
  );
}
