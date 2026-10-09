import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { History as HistoryIcon, RefreshCw } from "lucide-react";
import { api } from "../api.js";
import { useApp } from "../context/AppContext.jsx";
import {
  Badge, Button, EmptyState, ErrorBox, Loading, PageIntro, Panel, ScanStatusBadge, cn, formatDate,
} from "../components/ui.jsx";

const TYPES = [["all", "All"], ["repository", "Repositories"], ["upload", "Uploads"], ["website", "Websites"], ["demo", "Demo"]];

export default function History() {
  const navigate = useNavigate();
  const { scans, scansLoaded, refreshScans, currentScanId, setCurrentScanId, runScan, activeScan } = useApp();
  const [type, setType] = useState("all");
  const [error, setError] = useState("");
  const rows = scans.filter((s) => type === "all" || s.source_type === type);

  async function rescan(s) {
    setError("");
    try {
      const r = await runScan(s.label, () => api.scanRepo(s.url, s.branch));
      navigate(`/reports/${r.scan_id}`);
    } catch (e) {
      setError(e.message);
    }
  }

  return (
    <>
      <PageIntro
        title="Scan history"
        description="Scans recorded in this workspace, newest first. Stored in server memory - cleared when the backend restarts."
        actions={<Button onClick={refreshScans}><RefreshCw className="h-4 w-4" />Refresh</Button>}
      />
      {error && <div className="mb-4"><ErrorBox title="Re-scan failed">{error}</ErrorBox></div>}
      <div className="mb-4 flex flex-wrap gap-2">
        {TYPES.map(([k, l]) => (
          <button key={k} onClick={() => setType(k)} className={cn("rounded-full border px-3 py-1 text-xs", type === k ? "border-teal-500/60 bg-teal-500/10 text-teal-200" : "border-slate-800 text-slate-400 hover:text-slate-200")}>{l}</button>
        ))}
      </div>
      <Panel bodyClass="p-0">
        {!scansLoaded ? <Loading /> : rows.length === 0 ? (
          <EmptyState icon={HistoryIcon} title="No scans yet" action={<Button variant="primary" onClick={() => navigate("/scan/new")}>New Scan</Button>} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] text-left text-sm">
              <thead className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-500">
                <tr><th className="px-5 py-2.5 font-medium">Source</th><th className="py-2.5 font-medium">Type</th><th className="py-2.5 font-medium">Status</th><th className="py-2.5 font-medium">Results</th><th className="py-2.5 font-medium">When</th><th className="py-2.5 pr-5 text-right font-medium">Actions</th></tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {rows.map((s) => (
                  <tr key={s.scan_id} className={cn(s.scan_id === currentScanId && "bg-teal-500/5")}>
                    <td className="max-w-xs px-5 py-3">
                      <Link to={`/reports/${s.scan_id}`} className="block truncate text-slate-100 hover:text-teal-300">{s.label}{s.branch ? `@${s.branch}` : ""}</Link>
                      <span className="font-mono text-[11px] text-slate-500">{s.scan_id}</span>
                    </td>
                    <td className="py-3"><div className="flex gap-1">{s.mode === "demo" ? <Badge tone="violet">Demo</Badge> : <Badge>{s.source_type}</Badge>}</div></td>
                    <td className="py-3"><ScanStatusBadge status={s.status} /></td>
                    <td className="py-3 text-xs text-slate-400">
                      {s.summary ? `${s.summary.total_findings} findings - ${s.summary.vulnerable_packages}/${s.summary.total_packages} packages vulnerable`
                        : `${s.website_counts.technologies} technologies - ${s.website_counts.potential_exposures} potential exposures`}
                    </td>
                    <td className="py-3 text-xs text-slate-400">{formatDate(s.created_at)}</td>
                    <td className="py-3 pr-5">
                      <div className="flex justify-end gap-1.5">
                        <Button size="sm" onClick={() => navigate(`/reports/${s.scan_id}`)}>Report</Button>
                        {s.kind === "dependency" && s.scan_id !== currentScanId && <Button size="sm" variant="ghost" onClick={() => setCurrentScanId(s.scan_id)}>Set current</Button>}
                        {s.source_type === "repository" && <Button size="sm" variant="ghost" disabled={!!activeScan} onClick={() => rescan(s)}><RefreshCw className="h-3.5 w-3.5" />Re-scan</Button>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}
