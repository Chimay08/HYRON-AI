import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import {
  Boxes, FlaskConical, FolderGit2, Layers, Network, Plus, ScanSearch, ShieldAlert, Siren,
} from "lucide-react";
import { api } from "../api.js";
import { useApp, useReport } from "../context/AppContext.jsx";
import SummaryCards from "../components/SummaryCards.jsx";
import {
  Badge, Button, EmptyState, ErrorBox, EvidenceBadge, Loading, PageIntro, Panel, SEVERITY_COLORS,
  SEVERITY_ORDER, ScanStatusBadge, ScoreBadge, SeverityBadge, evidenceKind, formatDate,
} from "../components/ui.jsx";

function sourceKey(s) {
  if (s.source_type === "repository") return `repo:${s.label}@${s.branch}`;
  return `${s.source_type}:${s.label}`;
}

const tooltipStyle = {
  contentStyle: { background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8, fontSize: 12 },
  labelStyle: { color: "#e2e8f0" },
  itemStyle: { color: "#cbd5e1" },
};

export default function Overview() {
  const navigate = useNavigate();
  const { scans, scansLoaded, runScan, activeScan } = useApp();
  const [includeDemo, setIncludeDemo] = useState(true);
  const [demoError, setDemoError] = useState("");

  const depScans = useMemo(
    () => scans.filter((s) => s.kind === "dependency" && (includeDemo || s.mode !== "demo")),
    [scans, includeDemo],
  );
  // Aggregate the latest scan of each source so re-scans are not double counted.
  const latest = useMemo(() => {
    const seen = new Map();
    for (const s of depScans) if (!seen.has(sourceKey(s))) seen.set(sourceKey(s), s);
    return [...seen.values()];
  }, [depScans]);
  const usesDemo = latest.some((s) => s.mode === "demo");
  const sum = (fn) => latest.reduce((acc, s) => acc + fn(s.summary), 0);

  const severity = useMemo(() => {
    const totals = Object.fromEntries(SEVERITY_ORDER.map((k) => [k, 0]));
    latest.forEach((s) => Object.entries(s.summary.severity_counts).forEach(([k, v]) => { totals[k in totals ? k : "UNKNOWN"] += v; }));
    return SEVERITY_ORDER.map((k) => ({ name: k, value: totals[k] })).filter((d) => d.value > 0);
  }, [latest]);

  const trend = useMemo(() => [...depScans].reverse().map((s) => ({
    t: formatDate(s.created_at),
    risk: s.summary.total_risk,
    high: s.summary.high_priority_findings,
    findings: s.summary.total_findings,
    demo: s.mode === "demo",
  })), [depScans]);

  const newest = depScans[0];
  const { report: newestReport, loading: reportLoading, error: reportError } = useReport(newest?.scan_id ?? null);

  async function demo() {
    setDemoError("");
    try {
      const r = await runScan("demo scenario", api.demo);
      navigate(`/reports/${r.scan_id}`);
    } catch (e) {
      setDemoError(e.message);
    }
  }

  const demoBadge = usesDemo ? <Badge tone="violet">Demo Data</Badge> : null;
  const repoCount = new Set(latest.filter((s) => s.source_type === "repository").map((s) => s.label)).size;
  const critical = latest.reduce((a, s) => a + (s.summary.severity_counts.CRITICAL ?? 0), 0);

  if (!scansLoaded) return <Loading label="Loading workspace..." />;

  if (!scans.some((s) => s.kind === "dependency")) {
    return (
      <>
        <PageIntro title="Security overview" description="Your workspace has no scans yet. Start with the offline demo or scan your own dependencies." />
        {demoError && <div className="mb-4"><ErrorBox>{demoError}</ErrorBox></div>}
        <Panel>
          <EmptyState icon={ShieldAlert} title="See the risk. Trace the impact. Fix it."
            action={
              <div className="flex flex-wrap justify-center gap-2">
                <Button variant="primary" size="lg" onClick={() => navigate("/scan/new")}><Plus className="h-4 w-4" />New Scan</Button>
                <Button size="lg" onClick={demo} loading={!!activeScan}><FlaskConical className="h-4 w-4" />Run demo scan</Button>
              </div>
            }>
            Connect a GitHub repository, upload manifests and lockfiles, or passively inspect a public website.
            The demo runs offline with clearly labelled simulated data - no credentials required.
          </EmptyState>
        </Panel>
      </>
    );
  }

  return (
    <>
      <PageIntro
        title="Security overview"
        description="Aggregated from the latest scan of each source recorded in this workspace."
        actions={
          <>
            <label className="flex items-center gap-2 text-xs text-slate-400">
              <input type="checkbox" checked={includeDemo} onChange={(e) => setIncludeDemo(e.target.checked)} className="accent-teal-500" />
              Include demo scans
            </label>
            <Button variant="primary" onClick={() => navigate("/scan/new")}><ScanSearch className="h-4 w-4" />New Scan</Button>
          </>
        }
      />
      {usesDemo && (
        <div className="mb-4 flex items-center gap-2 rounded-lg border border-violet-500/30 bg-violet-500/10 px-3 py-2 text-xs text-violet-100">
          <FlaskConical className="h-3.5 w-3.5" /> Figures include <strong>Demo Data</strong> (simulated). Untick "Include demo scans" to see only real scans.
        </div>
      )}

      <SummaryCards items={[
        { label: "Repositories scanned", value: repoCount, sub: `${latest.length} source(s) total`, icon: FolderGit2 },
        { label: "Packages analysed", value: sum((s) => s.total_packages), sub: `${sum((s) => s.unscanned_packages)} not scanned`, icon: Boxes, badge: demoBadge },
        { label: "Vulnerabilities", value: sum((s) => s.total_findings), sub: `${sum((s) => s.vulnerable_packages)} vulnerable packages`, icon: ShieldAlert, tone: sum((s) => s.total_findings) ? "orange" : "green", badge: demoBadge },
        { label: "High / critical", value: sum((s) => s.high_priority_findings), sub: "V-RPS >= 60", icon: Siren, tone: sum((s) => s.high_priority_findings) ? "red" : "green", badge: demoBadge },
        { label: "Critical severity", value: critical, sub: "CVSS >= 9.0", icon: Layers, tone: critical ? "red" : "green", badge: demoBadge },
        { label: "Affected projects", value: sum((s) => s.affected_projects), sub: `of ${sum((s) => s.total_projects)} projects`, icon: Network, tone: sum((s) => s.affected_projects) ? "amber" : "green", badge: demoBadge },
      ]} />

      <div className="mt-6 grid gap-6 xl:grid-cols-3">
        <Panel title="Severity distribution" description="Advisory severity across the latest scans (separate from risk priority)" actions={demoBadge}>
          {severity.length === 0 ? (
            <EmptyState title="No vulnerabilities recorded" />
          ) : (
            <div className="flex flex-col items-center gap-4 sm:flex-row xl:flex-col 2xl:flex-row">
              <div className="shrink-0">
                <PieChart width={180} height={180}>
                  <Pie data={severity} dataKey="value" nameKey="name" innerRadius={52} outerRadius={80} paddingAngle={2} stroke="none" isAnimationActive={false}>
                    {severity.map((d) => <Cell key={d.name} fill={SEVERITY_COLORS[d.name]} />)}
                  </Pie>
                  <Tooltip {...tooltipStyle} />
                </PieChart>
              </div>
              <ul className="w-full space-y-2 text-sm">
                {severity.map((d) => (
                  <li key={d.name} className="flex items-center justify-between gap-3">
                    <span className="flex items-center gap-2 text-slate-300"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: SEVERITY_COLORS[d.name] }} />{d.name}</span>
                    <span className="font-mono tabular-nums text-slate-200">{d.value}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Panel>

        <Panel className="xl:col-span-2" title="Risk trend" description="Sum of V-RPS values per recorded scan, oldest to newest" actions={trend.some((p) => p.demo) ? <Badge tone="violet">Includes Demo Data</Badge> : null}>
          {trend.length < 2 ? (
            <EmptyState title="Not enough history yet">Run at least two scans to see a trend. Only real recorded scans are plotted - nothing is extrapolated.</EmptyState>
          ) : (
            <div className="h-56">
              <ResponsiveContainer>
                <AreaChart data={trend} margin={{ left: -16, right: 8, top: 8 }}>
                  <defs>
                    <linearGradient id="risk" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#14b8a6" stopOpacity={0.35} />
                      <stop offset="100%" stopColor="#14b8a6" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="t" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip {...tooltipStyle} />
                  <Area type="monotone" dataKey="risk" name="Total risk" stroke="#2dd4bf" fill="url(#risk)" strokeWidth={2} />
                  <Area type="monotone" dataKey="high" name="High-priority findings" stroke="#f87171" fill="none" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-5">
        <Panel className="xl:col-span-3" title="Recent findings" description={newest ? `Top risks from the latest scan: ${newest.label}` : ""}
          actions={<Button size="sm" onClick={() => navigate("/findings")}>View all</Button>} bodyClass="p-0">
          {reportLoading && <Loading />}
          {reportError && <div className="p-4"><ErrorBox>{reportError}</ErrorBox></div>}
          {newestReport && newestReport.findings.length === 0 && <EmptyState title="No known vulnerabilities in the latest scan">Not a guarantee of safety - check coverage gaps in the report.</EmptyState>}
          {newestReport && newestReport.findings.length > 0 && (
            <ul className="divide-y divide-slate-800">
              {newestReport.findings.slice(0, 6).map((f) => (
                <li key={f.finding_id}>
                  <Link to={`/findings?q=${encodeURIComponent(f.vulnerability.id)}`} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3 hover:bg-slate-800/40">
                    <div className="min-w-0 max-w-full flex-1">
                      <p className="truncate font-mono text-sm text-slate-100">{f.package}@{f.version}</p>
                      <p className="mt-0.5 flex flex-wrap items-center gap-1.5 text-xs text-slate-500">
                        <span className="font-mono">{f.vulnerability.id}</span>
                        <EvidenceBadge kind={evidenceKind(f.vulnerability)} />
                        <span>{f.exposure.affected_projects} project(s)</span>
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <SeverityBadge label={f.vulnerability.severity_label} />
                      <ScoreBadge score={f.max_risk.score} priority={f.max_risk.priority} provisional={f.max_risk.provisional} urgent={f.max_risk.urgent_review} />
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel className="xl:col-span-2" title="Recent scans" actions={<Button size="sm" onClick={() => navigate("/history")}>History</Button>} bodyClass="p-0">
          <ul className="divide-y divide-slate-800">
            {scans.slice(0, 6).map((s) => (
              <li key={s.scan_id}>
                <Link to={`/reports/${s.scan_id}`} className="flex items-center justify-between gap-3 px-5 py-3 hover:bg-slate-800/40">
                  <div className="min-w-0">
                    <p className="truncate text-sm text-slate-200">{s.label}{s.branch ? `@${s.branch}` : ""}</p>
                    <p className="text-xs text-slate-500">{s.kind === "website" ? "Website inspection" : s.source_type} - {formatDate(s.created_at)}</p>
                  </div>
                  <div className="flex shrink-0 items-center gap-1.5">
                    {s.mode === "demo" && <Badge tone="violet">Demo</Badge>}
                    <ScanStatusBadge status={s.status} />
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        </Panel>
      </div>
    </>
  );
}
