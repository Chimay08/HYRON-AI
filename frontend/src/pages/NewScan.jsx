import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  CheckCircle2, FileUp, FlaskConical, FolderGit2, GitBranch, Globe, KeyRound, Lock, ShieldCheck, Unlock,
} from "lucide-react";
import { api, errorMessage } from "../api.js";
import { useApp } from "../context/AppContext.jsx";
import UploadPanel from "../components/UploadPanel.jsx";
import WebsiteResult from "../components/WebsiteResult.jsx";
import {
  Badge, Button, ErrorBox, InputAction, Notice, PageIntro, Panel, cn,
} from "../components/ui.jsx";

const METHODS = [
  { id: "github", label: "GitHub repository", icon: FolderGit2, blurb: "Read manifests and lockfiles from an authorized repository" },
  { id: "upload", label: "Upload dependency files", icon: FileUp, blurb: "Manifests, lockfiles or resolved dependency trees" },
  { id: "website", label: "Public website URL", icon: Globe, blurb: "Passive technology inspection - not a full scan" },
];

function GitHubScan() {
  const navigate = useNavigate();
  const { meta, runScan } = useApp();
  const [url, setUrl] = useState("");
  const [info, setInfo] = useState(null);
  const [branch, setBranch] = useState("");
  const [state, setState] = useState({ status: "idle", error: "" });
  const tokenMode = meta?.integrations?.github?.token_configured;

  async function validate(e) {
    e?.preventDefault();
    setState({ status: "validating", error: "" });
    setInfo(null);
    try {
      const data = await api.validateRepo(url.trim(), null);
      setInfo(data);
      setBranch(data.branch);
      setState({ status: "validated", error: "" });
    } catch (err) {
      setState({ status: "error", error: errorMessage(err) });
    }
  }

  async function changeBranch(b) {
    setBranch(b);
    setState({ status: "validating", error: "" });
    try {
      setInfo(await api.validateRepo(url.trim(), b));
      setState({ status: "validated", error: "" });
    } catch (err) {
      setState({ status: "error", error: errorMessage(err) });
    }
  }

  async function scan() {
    setState({ status: "scanning", error: "" });
    try {
      const r = await runScan(info.full_name, () => api.scanRepo(url.trim(), branch));
      navigate(`/reports/${r.scan_id}`);
    } catch (err) {
      setState({ status: "validated", error: err.message });
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-3">
      <div className="space-y-5 lg:col-span-2">
        <form onSubmit={validate}>
          <InputAction
            id="repo-url"
            label="Repository URL"
            hint="https://github.com/owner/repo - a /tree/<branch> suffix is also accepted"
            error={state.status === "error" ? state.error : ""}
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              if (state.status === "error") setState({ status: "idle", error: "" });
            }}
            placeholder="https://github.com/owner/repository"
            required
            maxLength={300}
            action={<Button type="submit" size="field" loading={state.status === "validating"} disabled={!url.trim()}>Validate access</Button>}
          />
        </form>

        {state.error && state.status !== "error" && <ErrorBox title="Scan failed">{state.error}</ErrorBox>}

        {info && (
          <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="rounded-xl border border-slate-800 bg-slate-950/60">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 px-5 py-4">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                <a href={info.html_url} target="_blank" rel="noreferrer noopener" className="font-mono text-sm text-white hover:underline">{info.full_name}</a>
                <Badge tone={info.private ? "amber" : "slate"}>{info.private ? <><Lock className="h-3 w-3" />Private</> : <><Unlock className="h-3 w-3" />Public</>}</Badge>
                <Badge tone="slate">{info.auth === "token" ? "server token" : "anonymous"}</Badge>
              </div>
              <label className="flex items-center gap-2 text-xs text-slate-400">
                <GitBranch className="h-3.5 w-3.5" />
                <select value={branch} onChange={(e) => changeBranch(e.target.value)} className="h-8 rounded-md border border-slate-700 bg-slate-900 px-2 text-sm text-slate-200">
                  {info.branches.map((b) => <option key={b} value={b}>{b}</option>)}
                </select>
              </label>
            </div>
            <div className="px-5 py-4">
              <p className="text-xs text-slate-500">Commit <span className="font-mono text-slate-300">{info.commit.slice(0, 12)}</span> will be scanned (pinned for reproducibility).</p>
              {info.manifests.length === 0 ? (
                <Notice className="mt-3">No supported dependency files were found on this branch. A repository URL alone cannot reveal dependencies.</Notice>
              ) : (
                <>
                  <p className="mt-3 text-xs font-medium text-slate-300">{info.manifests.length} dependency file(s) found</p>
                  <ul className="mt-2 grid gap-1 sm:grid-cols-2">
                    {info.manifests.map((m) => <li key={m} className="truncate font-mono text-xs text-slate-400">{m}</li>)}
                  </ul>
                  {!info.manifests.some((m) => /(package-lock\.json|npm-shrinkwrap\.json|poetry\.lock|dep(endency)?[-_]?tree.*\.txt)$/i.test(m)) && (
                    <Notice className="mt-3">No lockfiles found - only direct dependencies with declared ranges can be analysed; the transitive graph will be incomplete.</Notice>
                  )}
                </>
              )}
              {info.skipped.length > 0 && <p className="mt-2 text-xs text-slate-500">Skipped: {info.skipped.slice(0, 4).join(", ")}{info.skipped.length > 4 ? "..." : ""}</p>}
              <Button className="mt-4" variant="primary" size="lg" disabled={!info.manifests.length} loading={state.status === "scanning"} onClick={scan}>
                Scan {info.full_name}@{branch}
              </Button>
            </div>
          </motion.div>
        )}
      </div>

      <div className="space-y-4">
        <Panel title="Repository access" bodyClass="p-5 space-y-3 text-sm text-slate-400">
          <p className="flex items-center gap-2 text-slate-200"><KeyRound className="h-4 w-4 text-teal-400" />
            {tokenMode ? "Server-side GitHub token configured" : "Anonymous access (public repositories)"}
          </p>
          <p>HYRON AI never asks for your GitHub password and never sends tokens to the browser.</p>
          <p>
            For private repositories, an administrator sets a read-only fine-grained token (<code className="text-slate-300">Contents: read</code>) as
            <code className="text-slate-300"> GITHUB_TOKEN</code> on the backend. Only repositories that token can read are scannable.
          </p>
          <p>Files are downloaded as data and parsed; repository code is never executed.</p>
        </Panel>
      </div>
    </div>
  );
}

function WebsiteScan() {
  const { runScan } = useApp();
  const [url, setUrl] = useState("");
  const [ack, setAck] = useState(false);
  const [state, setState] = useState({ status: "idle", error: "", report: null });

  async function inspect(e) {
    e.preventDefault();
    setState({ status: "running", error: "", report: null });
    try {
      const report = await runScan(url.trim(), () => api.scanWebsite(url.trim()));
      setState({ status: "done", error: "", report });
    } catch (err) {
      setState({ status: "error", error: err.message, report: null });
    }
  }

  return (
    <div className="space-y-5">
      <Notice tone="amber" icon={ShieldCheck}>
        <p className="font-medium">Limited, passive inspection</p>
        <p className="mt-1 text-amber-100/80">
          HYRON AI makes one ordinary request for the page and reads public headers and markup. It does not crawl, probe or attempt exploits,
          and it cannot see a site's backend packages. Results are labelled <em>technology detected</em> or <em>potential exposure</em> - never
          confirmed vulnerabilities. Active security testing requires explicit written authorization from the site owner and is out of scope.
        </p>
      </Notice>
      <form onSubmit={inspect} className="space-y-3">
        <InputAction
          id="website-url"
          label="Public website URL"
          error={state.status === "error" ? state.error : ""}
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            if (state.status === "error") setState({ status: "idle", error: "", report: null });
          }}
          placeholder="https://example.com"
          required
          maxLength={500}
          action={<Button type="submit" variant="primary" size="field" disabled={!ack || !url.trim()} loading={state.status === "running"}>Inspect</Button>}
        />
        <label className="flex items-start gap-2 text-sm text-slate-300">
          <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} className="mt-1 accent-teal-500" />
          I understand this is a passive, read-only inspection of a publicly accessible page.
        </label>
      </form>
      {state.report && <WebsiteResult report={state.report} />}
    </div>
  );
}

export default function NewScan() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const method = METHODS.some((m) => m.id === params.get("method")) ? params.get("method") : "github";
  const { runScan, activeScan } = useApp();
  const [demoError, setDemoError] = useState("");

  async function upload(files, onProgress) {
    const r = await runScan(`${files.length} file(s)`, () => api.upload(files, onProgress));
    navigate(`/reports/${r.scan_id}`);
  }

  async function demo() {
    setDemoError("");
    try {
      const r = await runScan("demo scenario", api.demo);
      navigate(`/reports/${r.scan_id}`);
    } catch (e) {
      setDemoError(e.message);
    }
  }

  return (
    <>
      <PageIntro title="New scan" description="Choose how HYRON AI should discover dependencies. Live scans use OSV.dev advisory data with CISA KEV and FIRST EPSS exploitation evidence." />

      <div className="mb-6 grid gap-3 md:grid-cols-3" role="tablist" aria-label="Scan method">
        {METHODS.map(({ id, label, icon: Icon, blurb }) => (
          <button
            key={id} role="tab" aria-selected={method === id}
            onClick={() => setParams({ method: id })}
            className={cn(
              "flex items-start gap-3 rounded-xl border p-4 text-left transition-colors",
              method === id ? "border-teal-500/60 bg-teal-500/5" : "border-slate-800 bg-slate-900/60 hover:border-slate-700",
            )}
          >
            <span className={cn("rounded-lg p-2", method === id ? "bg-teal-500/15 text-teal-300" : "bg-slate-800 text-slate-400")}><Icon className="h-4 w-4" /></span>
            <span>
              <span className="block text-sm font-medium text-white">{label}</span>
              <span className="mt-0.5 block text-xs text-slate-400">{blurb}</span>
            </span>
          </button>
        ))}
      </div>

      <Panel>
        {method === "github" && <GitHubScan />}
        {method === "upload" && (
          <div className="grid gap-6 lg:grid-cols-3">
            <div className="lg:col-span-2"><UploadPanel onScan={upload} /></div>
            <Panel title="What each file gives you" bodyClass="p-5 text-sm text-slate-400 space-y-2">
              <p><span className="text-slate-200">Lockfiles</span> (package-lock.json, poetry.lock, Maven dependency-tree): resolved versions and the full transitive graph.</p>
              <p><span className="text-slate-200">Manifests</span> (package.json, requirements.txt, pyproject.toml, pom.xml): direct dependencies only; ranges are scanned at their lower bound and flagged.</p>
              <p>Upload a manifest together with its lockfile - they are paired automatically.</p>
              <p className="text-xs text-slate-500">Files are parsed as data and never executed. Only package name, ecosystem and version are sent to OSV.dev.</p>
            </Panel>
          </div>
        )}
        {method === "website" && <WebsiteScan />}
      </Panel>

      <div className="mt-6 flex flex-col items-start justify-between gap-4 rounded-xl border border-violet-500/30 bg-violet-500/5 p-5 sm:flex-row sm:items-center">
        <div className="flex gap-3">
          <FlaskConical className="mt-0.5 h-5 w-5 shrink-0 text-violet-300" />
          <div>
            <p className="text-sm font-medium text-white">Demo scenario <Badge tone="violet" className="ml-1">Simulated</Badge></p>
            <p className="mt-0.5 text-sm text-slate-400">Five fictional services and synthetic advisories (HYRON-DEMO-*). Runs offline, needs no credentials, and is labelled as simulated everywhere.</p>
          </div>
        </div>
        <Button onClick={demo} loading={!!activeScan && activeScan.label === "demo scenario"}>Run demo scan</Button>
      </div>
      {demoError && <div className="mt-3"><ErrorBox>{demoError}</ErrorBox></div>}
    </>
  );
}
