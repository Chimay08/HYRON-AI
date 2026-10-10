import { useState } from "react";
import { CheckCircle2, CircleSlash, KeyRound } from "lucide-react";
import { getWorkspaceId, resetWorkspaceId } from "../api.js";
import { useApp } from "../context/AppContext.jsx";
import { Badge, Button, Loading, Modal, PageIntro, Panel } from "../components/ui.jsx";

function Integration({ name, ok, detail }) {
  return (
    <li className="flex items-start justify-between gap-3 py-3">
      <div>
        <p className="text-sm text-slate-200">{name}</p>
        <p className="text-xs text-slate-500">{detail}</p>
      </div>
      {ok ? <Badge tone="green"><CheckCircle2 className="h-3 w-3" />Active</Badge> : <Badge><CircleSlash className="h-3 w-3" />Not configured</Badge>}
    </li>
  );
}

export default function Settings() {
  const { meta, health, setCurrentScanId } = useApp();
  const [confirm, setConfirm] = useState(false);
  const [ws, setWs] = useState(getWorkspaceId());

  function regenerate() {
    setWs(resetWorkspaceId());
    setCurrentScanId(null);
    setConfirm(false);
    window.location.assign("/");
  }

  const i = meta?.integrations;
  const risk = meta?.risk_model;

  return (
    <>
      <PageIntro title="Settings" description="Workspace, integrations, risk model and data handling. Secrets are configured on the backend only and are never shown here." />
      <div className="grid gap-5 xl:grid-cols-2">
        <Panel title="Workspace" description="Demo profile - no sign-in">
          <p className="text-sm text-slate-400">
            Scans are stored per workspace on the server. This browser's workspace ID is generated randomly and sent with each request.
            It separates casual users but is <strong className="text-slate-200">not authentication</strong> - do not use this prototype for confidential data on a shared server.
          </p>
          <p className="mt-3 break-all rounded-lg bg-slate-950 px-3 py-2 font-mono text-xs text-slate-300">{ws}</p>
          <Button className="mt-3" variant="danger" onClick={() => setConfirm(true)}>Start a new workspace</Button>
        </Panel>

        <Panel title="Integrations" bodyClass="px-5 py-1">
          {!meta ? <Loading /> : (
            <ul className="divide-y divide-slate-800">
              <Integration name="OSV.dev" ok={i.osv.enabled} detail="Vulnerability advisories - no credentials required" />
              <Integration name="CISA Known Exploited Vulnerabilities" ok={i.cisa_kev.enabled} detail="Public catalogue, cached 12 h" />
              <Integration name="FIRST EPSS" ok={i.first_epss.enabled} detail="Exploit prediction scores, cached 12 h" />
              <Integration name="GitHub" ok detail={`Mode: ${i.github.mode}. ${i.github.token_configured ? "Private repositories readable by the server token are available." : "Set GITHUB_TOKEN on the backend for private repositories."}`} />
              <Integration name="AI Security Copilot" ok={i.ai_copilot.enabled}
                detail={i.ai_copilot.enabled ? `${i.ai_copilot.provider} (${i.ai_copilot.model}). Private-repo data ${i.ai_copilot.private_data_allowed ? "may" : "is never"} sent.` : "Set ANTHROPIC_API_KEY on the backend. Without it, deterministic explanations are used."} />
            </ul>
          )}
        </Panel>

        <Panel title="V-RPS" description="Project-specific remediation-priority heuristic - not an industry standard">
          {!risk ? <Loading /> : (
            <div className="space-y-3 text-sm text-slate-400">
              <p className="rounded-lg bg-slate-950 px-3 py-2 font-mono text-xs text-teal-200">{risk.formula}</p>
              <ul className="space-y-1">
                <li>Weights: severity {risk.weights.severity}, exploit evidence {risk.weights.exploit_evidence}, exposure {risk.weights.exposure}, propagation {risk.weights.propagation}.</li>
                <li>Exploit evidence: CISA KEV = 100, otherwise EPSS probability x 100.</li>
                <li>Runtime factor: production {risk.weights.runtime_factors.production}, development {risk.weights.runtime_factors.development}, unknown {risk.weights.runtime_factors.unknown}.</li>
                <li>Propagation: {risk.weights.propagation_points_per_project} points per distinct affected project, capped at 100.</li>
                <li>Missing evidence uses disclosed neutral placeholders and marks the score provisional.</li>
                <li>Priority: critical &gt;= {risk.priority_thresholds.critical}, high &gt;= {risk.priority_thresholds.high}, medium &gt;= {risk.priority_thresholds.medium}.</li>
              </ul>
            </div>
          )}
        </Panel>

        <Panel title="Data handling & limits">
          <ul className="list-disc space-y-1.5 pl-5 text-sm text-slate-400">
            <li>Only package name, ecosystem and version are sent to OSV.dev; only CVE IDs to FIRST EPSS.</li>
            <li>Uploaded files and repository contents are parsed as data and never executed.</li>
            <li>GitHub and AI credentials live in backend environment variables and are never returned to the browser.</li>
            <li>Website inspection is a single passive GET with SSRF protection; private and internal addresses are refused.</li>
            <li>Results are kept in server memory and disappear on restart.</li>
            {meta && <li>Limits: {meta.limits.max_files} files per upload, manifests {meta.limits.manifest_bytes / 1e6} MB, lockfiles {meta.limits.lockfile_bytes / 1e6} MB, {meta.limits.scan_rate_limit}.</li>}
          </ul>
          <p className="mt-4 flex items-center gap-2 text-xs text-slate-500"><KeyRound className="h-3.5 w-3.5" />API {health.status === "ok" ? `v${health.version} online` : "offline"} - <a className="text-teal-300 hover:underline" href="/docs" target="_blank" rel="noreferrer">API documentation</a></p>
        </Panel>
      </div>

      <Modal open={confirm} onClose={() => setConfirm(false)} title="Start a new workspace?"
        footer={<><Button variant="ghost" onClick={() => setConfirm(false)}>Cancel</Button><Button variant="danger" onClick={regenerate}>Start new workspace</Button></>}>
        This browser will switch to a fresh workspace ID. Scans in the current workspace stay on the server until it restarts but will no longer be visible here.
      </Modal>
    </>
  );
}
