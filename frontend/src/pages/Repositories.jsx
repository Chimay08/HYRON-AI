import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { FolderGit2, GitBranch, Plus, RefreshCw } from "lucide-react";
import { api } from "../api.js";
import { useApp } from "../context/AppContext.jsx";
import {
  Badge, Button, EmptyState, ErrorBox, Loading, PageIntro, Panel, ScanStatusBadge, formatDate,
} from "../components/ui.jsx";

export default function Repositories() {
  const navigate = useNavigate();
  const { scans, scansLoaded, runScan, activeScan, setCurrentScanId } = useApp();
  const [error, setError] = useState("");

  const repos = useMemo(() => {
    const map = new Map();
    for (const s of scans.filter((x) => x.source_type === "repository")) {
      const key = `${s.label}@${s.branch}`;
      const entry = map.get(key) ?? { key, label: s.label, branch: s.branch, url: s.url, scans: [] };
      entry.scans.push(s);
      map.set(key, entry);
    }
    return [...map.values()];
  }, [scans]);

  async function rescan(repo) {
    setError("");
    try {
      const r = await runScan(repo.label, () => api.scanRepo(repo.url, repo.branch));
      navigate(`/reports/${r.scan_id}`);
    } catch (e) {
      setError(e.message);
    }
  }

  return (
    <>
      <PageIntro
        title="Repositories"
        description="GitHub repositories scanned in this workspace. Re-scanning pins the current branch head and verifies fixes against the previous scan."
        actions={<Button variant="primary" onClick={() => navigate("/scan/new?method=github")}><Plus className="h-4 w-4" />Add repository</Button>}
      />
      {error && <div className="mb-4"><ErrorBox title="Re-scan failed">{error}</ErrorBox></div>}
      {!scansLoaded ? <Loading /> : repos.length === 0 ? (
        <Panel>
          <EmptyState icon={FolderGit2} title="No repositories scanned yet"
            action={<Button variant="primary" onClick={() => navigate("/scan/new?method=github")}>Connect a repository</Button>}>
            Public repositories work without credentials. Private repositories need a server-side GitHub token (see Settings).
          </EmptyState>
        </Panel>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {repos.map((repo) => {
            const latest = repo.scans[0];
            const prev = repo.scans[1];
            const delta = prev ? latest.summary.total_findings - prev.summary.total_findings : null;
            return (
              <div key={repo.key} className="flex flex-col rounded-xl border border-slate-800 bg-slate-900/60 p-5">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <a href={repo.url} target="_blank" rel="noreferrer noopener" className="block truncate font-mono text-sm text-white hover:underline">{repo.label}</a>
                    <p className="mt-0.5 flex items-center gap-1 text-xs text-slate-500"><GitBranch className="h-3 w-3" />{repo.branch}</p>
                  </div>
                  <ScanStatusBadge status={latest.status} />
                </div>
                <div className="mt-4 grid grid-cols-3 gap-2 text-center">
                  <div><p className="text-lg font-semibold text-white">{latest.summary.total_packages}</p><p className="text-[11px] text-slate-500">packages</p></div>
                  <div><p className="text-lg font-semibold text-orange-300">{latest.summary.total_findings}</p><p className="text-[11px] text-slate-500">findings</p></div>
                  <div><p className="text-lg font-semibold text-red-300">{latest.summary.high_priority_findings}</p><p className="text-[11px] text-slate-500">high / critical</p></div>
                </div>
                <p className="mt-3 text-xs text-slate-500">
                  Last scanned {formatDate(latest.created_at)} - {repo.scans.length} scan(s)
                  {delta !== null && <Badge tone={delta < 0 ? "green" : delta > 0 ? "red" : "slate"} className="ml-2">{delta > 0 ? "+" : ""}{delta} since previous</Badge>}
                </p>
                <div className="mt-4 flex flex-wrap gap-2">
                  <Button size="sm" onClick={() => { setCurrentScanId(latest.scan_id); navigate("/findings"); }}>Findings</Button>
                  <Button size="sm" onClick={() => navigate(`/reports/${latest.scan_id}`)}>Report</Button>
                  <Button size="sm" variant="ghost" disabled={!!activeScan} onClick={() => rescan(repo)}><RefreshCw className="h-3.5 w-3.5" />Re-scan</Button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}
