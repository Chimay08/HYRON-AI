import { useRef, useState } from "react";
import { FileCode2, RotateCcw, Trash2, UploadCloud } from "lucide-react";
import { Button, ErrorBox, cn } from "./ui.jsx";

const MAX_FILES = 10;
const LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json", "poetry.lock"];

function kindOf(name) {
  const n = name.toLowerCase();
  if (n === "package.json") return { label: "npm manifest", lock: false };
  if (LOCKFILES.includes(n)) return { label: "lockfile", lock: true };
  if (n === "pyproject.toml") return { label: "Python project", lock: false };
  if (n === "pom.xml") return { label: "Maven POM", lock: false };
  if (n.endsWith(".txt") && /dep(endency)?[-_]?tree/.test(n)) return { label: "Maven dependency tree", lock: true };
  if (n.endsWith(".txt") && n.includes("requirements")) return { label: "pip requirements", lock: false };
  if (n.endsWith(".json")) return { label: "dependency-tree JSON", lock: true };
  return null;
}

export function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

function validate(file) {
  const kind = kindOf(file.name);
  if (!kind) return "unsupported file type";
  const limit = kind.lock ? 5_000_000 : 1_000_000;
  if (file.size > limit) return `larger than ${limit / 1_000_000} MB`;
  if (file.size === 0) return "file is empty";
  return null;
}

export default function UploadPanel({ onScan }) {
  const [files, setFiles] = useState([]);
  const [rejected, setRejected] = useState([]);
  const [dragging, setDragging] = useState(false);
  const [state, setState] = useState({ status: "idle", progress: null, error: "" });
  const input = useRef(null);
  const busy = state.status === "uploading" || state.status === "scanning";

  function add(list) {
    const next = [...files];
    const bad = [];
    for (const f of list) {
      const problem = validate(f);
      if (problem) bad.push(`${f.name}: ${problem}`);
      else if (next.length >= MAX_FILES) bad.push(`${f.name}: at most ${MAX_FILES} files`);
      else if (!next.some((x) => x.name === f.name)) next.push(f);
      else bad.push(`${f.name}: already added`);
    }
    setFiles(next);
    setRejected(bad);
    if (state.status === "error") setState({ status: "idle", progress: null, error: "" });
  }

  async function scan() {
    setState({ status: "uploading", progress: 0, error: "" });
    try {
      await onScan(files, (p) => setState((s) => ({ ...s, status: p === 100 ? "scanning" : "uploading", progress: p })));
    } catch (e) {
      setState({ status: "error", progress: null, error: e.message });
      return;
    }
    setState({ status: "idle", progress: null, error: "" });
  }

  const hasManifestOnly = files.some((f) => f.name.toLowerCase() === "package.json") &&
    !files.some((f) => ["package-lock.json", "npm-shrinkwrap.json"].includes(f.name.toLowerCase()));

  return (
    <div className="space-y-4">
      <div
        role="button" tabIndex={0}
        onClick={() => !busy && input.current?.click()}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current?.click()}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => { e.preventDefault(); setDragging(false); if (!busy) add(e.dataTransfer.files); }}
        className={cn(
          "flex cursor-pointer flex-col items-center rounded-xl border-2 border-dashed px-6 py-10 text-center transition-colors",
          dragging ? "border-teal-400 bg-teal-500/5" : "border-slate-700 hover:border-teal-500/50 hover:bg-slate-900",
        )}
      >
        <UploadCloud className="mb-3 h-8 w-8 text-teal-400" />
        <p className="text-sm font-medium text-slate-100">Drop dependency files here, or <span className="text-teal-300 underline underline-offset-2">browse</span></p>
        <p className="mt-1.5 max-w-lg text-xs text-slate-500">
          package.json, package-lock.json, npm-shrinkwrap.json, requirements*.txt, pyproject.toml, poetry.lock, pom.xml,
          Maven <code>dependency-tree.txt</code> - manifests up to 1 MB, lockfiles up to 5 MB, max {MAX_FILES} files
        </p>
        <input ref={input} type="file" multiple hidden accept=".json,.txt,.xml,.lock,.toml" onChange={(e) => { add(e.target.files); e.target.value = ""; }} />
      </div>

      {rejected.length > 0 && (
        <ul className="space-y-1 rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-300">
          {rejected.map((r) => <li key={r}>{r}</li>)}
        </ul>
      )}

      {files.length > 0 && (
        <ul className="divide-y divide-slate-800 rounded-xl border border-slate-800">
          {files.map((f) => (
            <li key={f.name} className="flex items-center gap-3 px-4 py-2.5">
              <FileCode2 className="h-4 w-4 shrink-0 text-slate-500" />
              <div className="min-w-0 flex-1">
                <p className="truncate font-mono text-sm text-slate-100">{f.name}</p>
                <p className="text-xs text-slate-500">{kindOf(f.name)?.label} - {formatBytes(f.size)}</p>
              </div>
              <button disabled={busy} onClick={() => setFiles(files.filter((x) => x !== f))} className="rounded p-1.5 text-slate-500 hover:bg-slate-800 hover:text-red-300 disabled:opacity-40" aria-label={`Remove ${f.name}`}>
                <Trash2 className="h-4 w-4" />
              </button>
            </li>
          ))}
        </ul>
      )}

      {hasManifestOnly && (
        <p className="text-xs text-amber-300/90">
          package.json alone lists declared ranges and direct dependencies only. Add package-lock.json for resolved versions and the full transitive graph.
        </p>
      )}

      {busy && (
        <div>
          <div className="mb-1 flex justify-between text-xs text-slate-400">
            <span>{state.status === "uploading" ? "Uploading..." : "Scanning against OSV.dev, CISA KEV and FIRST EPSS..."}</span>
            {state.progress != null && <span>{state.progress}%</span>}
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-slate-800">
            <div className={cn("h-full rounded-full bg-teal-400 transition-all", state.status === "scanning" && "animate-pulse")} style={{ width: `${state.progress ?? 100}%` }} />
          </div>
        </div>
      )}

      {state.status === "error" && <ErrorBox title="Scan failed">{state.error}</ErrorBox>}

      <div className="flex flex-wrap items-center gap-2">
        <Button variant="primary" size="lg" disabled={!files.length} loading={busy} onClick={scan}>
          {state.status === "error" ? <><RotateCcw className="h-4 w-4" />Retry scan</> : `Scan ${files.length || ""} file${files.length === 1 ? "" : "s"}`}
        </Button>
        {files.length > 0 && !busy && <Button variant="ghost" onClick={() => { setFiles([]); setRejected([]); }}>Clear</Button>}
      </div>
    </div>
  );
}
