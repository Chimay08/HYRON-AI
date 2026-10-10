import { useEffect, useMemo, useRef, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import {
  ChevronDown, ChevronRight, FolderGit2, History, LayoutDashboard, Loader2, Menu, Network, ScanSearch,
  Search, Settings, ShieldAlert, UserRound, Wrench, X,
} from "lucide-react";
import { useApp } from "../context/AppContext.jsx";
import { getWorkspaceId } from "../api.js";
import { Badge, ScanStatusBadge, cn } from "../components/ui.jsx";

export const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/scan/new", label: "New Scan", icon: ScanSearch },
  { to: "/repositories", label: "Repositories", icon: FolderGit2 },
  { to: "/findings", label: "Vulnerability Findings", icon: ShieldAlert },
  { to: "/graph", label: "Dependency Graph", icon: Network },
  { to: "/remediation", label: "Remediation Center", icon: Wrench },
  { to: "/history", label: "Scan History", icon: History },
  { to: "/settings", label: "Settings", icon: Settings },
];

// The HYRON AI shield mark, shared by the sidebar and the compact (mobile) header.
function LogoMark({ className = "h-8 w-8" }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden="true">
      <path d="M16 2 4 7v8c0 7 5 12.5 12 15 7-2.5 12-8 12-15V7z" fill="#2AABA1" />
      <path d="M8 10.5h4v11H8zm12 0h4v11h-4zM12 14h8v4h-8z" fill="#071311" />
      <path d="M16 4.8 6.8 8.7v6.1c0 5.6 3.7 10 9.2 12.3" fill="none" stroke="#FFE2AF" strokeWidth="1" opacity=".72" />
    </svg>
  );
}

function Logo() {
  return (
    <Link to="/" className="flex items-center gap-2.5 px-2">
      <LogoMark />
      <div className="leading-tight">
        <p className="text-[15px] font-bold tracking-[0.08em] text-white">HYRON <span className="text-teal-400">AI</span></p>
        <p className="font-mono text-[9px] uppercase tracking-[0.18em] text-slate-500">Exposure intelligence</p>
      </div>
    </Link>
  );
}

function SidebarNav({ onNavigate }) {
  const { health } = useApp();
  return (
    <div className="flex h-full flex-col">
      <div className="flex h-16 items-center border-b border-slate-800 px-3"><Logo /></div>
      <nav className="flex-1 space-y-0.5 overflow-y-auto p-3" aria-label="Main">
        {NAV.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to} to={to} end={end} onClick={onNavigate}
            className={({ isActive }) => cn(
              "group flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
              isActive ? "bg-teal-500/10 text-teal-300" : "text-slate-400 hover:bg-slate-800/70 hover:text-slate-100",
            )}
          >
            <Icon className="h-4 w-4 shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="border-t border-slate-800 p-4 text-xs text-slate-500">
        <div className="flex items-center gap-2">
          <span className={cn("h-2 w-2 rounded-full", health.status === "ok" ? "bg-emerald-400" : health.status === "checking" ? "bg-slate-500" : "bg-red-400")} />
          {health.status === "ok" ? `API online - v${health.version}` : health.status === "checking" ? "Checking API..." : "API offline"}
        </div>
        <p className="mt-1.5 font-mono text-[10px] leading-4">OBSERVE / PRIORITIZE / REMEDIATE</p>
      </div>
    </div>
  );
}

const TITLES = {
  "/": ["Overview"],
  "/scan/new": ["Scans", "New Scan"],
  "/repositories": ["Scans", "Repositories"],
  "/findings": ["Analysis", "Vulnerability Findings"],
  "/graph": ["Analysis", "Dependency Graph"],
  "/remediation": ["Response", "Remediation Center"],
  "/history": ["Scans", "Scan History"],
  "/settings": ["Workspace", "Settings"],
};

function crumbsFor(pathname) {
  if (pathname.startsWith("/reports/")) return ["Reports", `Scan ${pathname.split("/")[2]}`];
  return TITLES[pathname] ?? ["Not found"];
}

function QuickSearch() {
  const navigate = useNavigate();
  const { currentScanId, cachedReport } = useApp();
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const report = currentScanId ? cachedReport(currentScanId) : null;

  const results = useMemo(() => {
    const term = q.trim().toLowerCase();
    if (!term) return [];
    const pages = NAV.filter((n) => n.label.toLowerCase().includes(term)).map((n) => ({ key: n.to, label: n.label, hint: "Page", to: n.to }));
    const findings = (report?.findings ?? [])
      .filter((f) => f.package.toLowerCase().includes(term) || f.vulnerability.id.toLowerCase().includes(term))
      .slice(0, 6)
      .map((f) => ({ key: f.finding_id, label: `${f.package}@${f.version}`, hint: f.vulnerability.id, to: `/findings?q=${encodeURIComponent(f.vulnerability.id)}` }));
    return [...pages, ...findings].slice(0, 8);
  }, [q, report]);

  function go(item) {
    navigate(item.to);
    setQ("");
    setOpen(false);
  }

  return (
    <div className="relative hidden w-72 md:block">
      <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
      <input
        value={q}
        onChange={(e) => { setQ(e.target.value); setOpen(true); }}
        onFocus={() => setOpen(true)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        onKeyDown={(e) => e.key === "Enter" && results[0] && go(results[0])}
        placeholder="Jump to page, package or advisory"
        aria-label="Quick navigation"
        className="h-9 w-full rounded-lg border border-slate-800 bg-slate-900 pl-9 pr-3 text-sm text-slate-200 placeholder:text-slate-500 focus:border-teal-500 focus:outline-none"
      />
      {open && q && (
        <div className="absolute left-0 right-0 top-11 z-40 overflow-hidden rounded-lg border border-slate-800 bg-slate-900 shadow-xl">
          {results.length === 0 ? (
            <p className="px-3 py-2.5 text-xs text-slate-500">No matches in pages or the current scan</p>
          ) : results.map((r) => (
            <button key={r.key} onMouseDown={() => go(r)} className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-sm text-slate-200 hover:bg-slate-800">
              <span className="truncate">{r.label}</span>
              <span className="shrink-0 font-mono text-[11px] text-slate-500">{r.hint}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function ScanStatus() {
  const { activeScan, scans, currentScanId } = useApp();
  const [, tick] = useState(0);
  useEffect(() => {
    if (!activeScan) return undefined;
    const t = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, [activeScan]);
  if (activeScan) {
    const secs = Math.round((Date.now() - activeScan.startedAt) / 1000);
    return (
      <span className="inline-flex items-center gap-2 rounded-lg border border-teal-500/30 bg-teal-500/10 px-2.5 py-1 text-xs text-teal-200">
        <Loader2 className="h-3.5 w-3.5 animate-spin" /> <span className="hidden sm:inline">Scanning {activeScan.label}</span> {secs}s
      </span>
    );
  }
  const current = scans.find((s) => s.scan_id === currentScanId);
  if (!current) return <span className="hidden text-xs text-slate-500 sm:inline">No active scan</span>;
  return (
    <Link to={`/reports/${current.scan_id}`} className="hidden items-center gap-2 text-xs text-slate-400 hover:text-slate-200 sm:inline-flex">
      {current.mode === "demo" && <Badge tone="violet">Demo</Badge>}
      <ScanStatusBadge status={current.status} />
    </Link>
  );
}

function ProfileMenu() {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    const close = (e) => ref.current && !ref.current.contains(e.target) && setOpen(false);
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);
  return (
    <div className="relative" ref={ref}>
      <button onClick={() => setOpen(!open)} className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-sm text-slate-300 hover:bg-slate-800" aria-haspopup="menu" aria-expanded={open}>
        <span className="flex h-7 w-7 items-center justify-center rounded-full bg-slate-800 text-slate-300"><UserRound className="h-4 w-4" /></span>
        <span className="hidden text-left leading-tight lg:block">
          <span className="block text-xs font-medium text-slate-200">Demo profile</span>
          <span className="block text-[10px] text-slate-500">Local workspace</span>
        </span>
        <ChevronDown className="h-3.5 w-3.5 text-slate-500" />
      </button>
      {open && (
        <div role="menu" className="absolute right-0 top-11 z-40 w-64 rounded-lg border border-slate-800 bg-slate-900 p-1 shadow-xl">
          <div className="border-b border-slate-800 px-3 py-2.5">
            <p className="text-sm font-medium text-white">Demo profile</p>
            <p className="text-xs text-slate-400">No sign-in. Scans are scoped to this browser's workspace.</p>
            <p className="mt-1 truncate font-mono text-[10px] text-slate-500">{getWorkspaceId()}</p>
          </div>
          <Link role="menuitem" to="/settings" onClick={() => setOpen(false)} className="block rounded-md px-3 py-2 text-sm text-slate-300 hover:bg-slate-800">Workspace settings</Link>
          <Link role="menuitem" to="/history" onClick={() => setOpen(false)} className="block rounded-md px-3 py-2 text-sm text-slate-300 hover:bg-slate-800">Scan history</Link>
          <a role="menuitem" href="/docs" target="_blank" rel="noreferrer" className="block rounded-md px-3 py-2 text-sm text-slate-300 hover:bg-slate-800">API documentation</a>
        </div>
      )}
    </div>
  );
}

export default function Layout() {
  const location = useLocation();
  const [drawer, setDrawer] = useState(false);
  const crumbs = crumbsFor(location.pathname);
  useEffect(() => setDrawer(false), [location.pathname]);

  return (
    <div className="app-shell min-h-screen bg-slate-950 text-slate-200">
      <aside className="app-chrome fixed inset-y-0 left-0 z-30 hidden w-64 border-r border-slate-800 bg-slate-950 lg:block">
        <SidebarNav />
      </aside>

      <AnimatePresence>
        {drawer && (
          <>
            <motion.div className="fixed inset-0 z-40 bg-slate-950/70 lg:hidden" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setDrawer(false)} />
            <motion.aside
              className="fixed inset-y-0 left-0 z-50 w-72 border-r border-slate-800 bg-slate-950 lg:hidden"
              initial={{ x: -288 }} animate={{ x: 0 }} exit={{ x: -288 }} transition={{ duration: 0.18 }}
            >
              <button className="absolute right-3 top-4 rounded p-1.5 text-slate-400 hover:bg-slate-800" onClick={() => setDrawer(false)} aria-label="Close menu"><X className="h-4 w-4" /></button>
              <SidebarNav onNavigate={() => setDrawer(false)} />
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      <div className="lg:pl-64">
        <header className="app-chrome sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-slate-800 bg-slate-950/90 px-4 backdrop-blur sm:px-6 print:hidden">
          <button className="rounded-lg p-2 text-slate-300 hover:bg-slate-800 lg:hidden" onClick={() => setDrawer(true)} aria-label="Open menu"><Menu className="h-5 w-5" /></button>
          <Link to="/" className="shrink-0 lg:hidden" aria-label="HYRON AI home"><LogoMark className="h-7 w-7" /></Link>
          <div className="min-w-0 flex-1">
            <nav aria-label="Breadcrumb" className="flex items-center gap-1 text-[11px] text-slate-500">
              <span>HYRON AI</span>
              {crumbs.slice(0, -1).map((c) => (<span key={c} className="flex items-center gap-1"><ChevronRight className="h-3 w-3" />{c}</span>))}
            </nav>
            <p className="truncate text-sm font-semibold text-white">{crumbs[crumbs.length - 1]}</p>
          </div>
          <QuickSearch />
          <ScanStatus />
          <ProfileMenu />
        </header>
        <main className="mx-auto max-w-[1400px] px-4 py-6 sm:px-6 lg:py-8">
          <motion.div key={location.pathname} initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.18 }}>
            <Outlet />
          </motion.div>
        </main>
      </div>
    </div>
  );
}
