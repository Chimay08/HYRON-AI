import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { AlertTriangle, Check, Copy, FlaskConical, Inbox, Loader2, RefreshCw, Siren, X } from "lucide-react";
import { useApp } from "../context/AppContext.jsx";

export const cn = (...parts) => parts.filter(Boolean).join(" ");

export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
export const SEVERITY_COLORS = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#38bdf8",
  UNKNOWN: "#64748b",
};
export const STATUS_COLORS = { vulnerable: "#ef4444", affected: "#f59e0b", clean: "#22c55e", unscanned: "#64748b" };
export const STATUS_LABELS = {
  vulnerable: "Vulnerable",
  affected: "Potentially affected",
  clean: "No known issues",
  unscanned: "Not scanned",
};

export function formatDate(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function shortName(name) {
  return name.replace(/^@[^/]+\//, "").split(":").pop();
}

// ------------------------------------------------------------------ layout

export function Panel({ title, description, actions, children, className, bodyClass = "p-5", id }) {
  return (
    // min-w-0 lets a panel shrink inside grid/flex layouts so long package names truncate
    // instead of widening the page on phones.
    <section id={id} className={cn("min-w-0 rounded-xl border border-slate-800 bg-slate-900/60", className)}>
      {(title || actions) && (
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800 px-5 py-4">
          <div className="min-w-0">
            {title && <h2 className="font-mono text-xs font-semibold uppercase tracking-[0.08em] text-white">{title}</h2>}
            {description && <p className="mt-0.5 text-xs text-slate-400">{description}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={bodyClass}>{children}</div>
    </section>
  );
}

export function PageIntro({ title, description, actions }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-tight text-white">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-sm text-slate-400">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Button({ variant = "secondary", size = "md", className, children, loading, ...props }) {
  const variants = {
    primary: "bg-teal-500 text-slate-950 hover:bg-teal-400 font-semibold",
    secondary: "border border-slate-700 bg-slate-900 text-slate-200 hover:border-teal-500/60 hover:text-white",
    ghost: "text-slate-300 hover:bg-slate-800 hover:text-white",
    danger: "border border-red-500/40 bg-red-500/10 text-red-200 hover:bg-red-500/20",
  };
  // "field" matches inputClass height so a button sits flush beside an input.
  const sizes = { sm: "h-8 px-2.5 text-xs", md: "h-9 px-3.5 text-sm", field: "h-10 px-5 text-sm", lg: "h-11 px-5 text-sm" };
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-lg transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        variants[variant], sizes[size], className,
      )}
      disabled={loading || props.disabled}
      {...props}
    >
      {loading && <Loader2 className="h-4 w-4 animate-spin" />}
      {children}
    </button>
  );
}

// ------------------------------------------------------------------ badges

const TONES = {
  red: "bg-red-500/10 text-red-300 ring-red-500/30",
  orange: "bg-orange-500/10 text-orange-300 ring-orange-500/30",
  amber: "bg-amber-500/10 text-amber-300 ring-amber-500/30",
  yellow: "bg-yellow-500/10 text-yellow-200 ring-yellow-500/30",
  green: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30",
  teal: "bg-teal-500/10 text-teal-300 ring-teal-500/30",
  sky: "bg-sky-500/10 text-sky-300 ring-sky-500/30",
  violet: "bg-violet-500/10 text-violet-300 ring-violet-500/30",
  slate: "bg-slate-500/10 text-slate-300 ring-slate-500/30",
};

export function Badge({ tone = "slate", children, className, title }) {
  return (
    <span title={title} className={cn("inline-flex items-center gap-1 whitespace-nowrap rounded-md px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset", TONES[tone], className)}>
      {children}
    </span>
  );
}

const SEV_TONE = { CRITICAL: "red", HIGH: "orange", MEDIUM: "yellow", LOW: "sky", UNKNOWN: "slate", NONE: "slate" };

export function SeverityBadge({ label, score, estimated }) {
  const text = label ?? "UNKNOWN";
  return (
    <Badge tone={SEV_TONE[text] ?? "slate"} title={estimated ? "Estimated from a qualitative label" : undefined}>
      {text}
      {score != null && <span className="font-mono opacity-80">{score.toFixed(1)}{estimated ? "*" : ""}</span>}
    </Badge>
  );
}

const PRIO_TONE = { critical: "red", high: "orange", medium: "amber", low: "slate" };

export function ScoreBadge({ score, priority, provisional, urgent }) {
  const badge = (
    <Badge tone={PRIO_TONE[priority]} title={provisional ? "Provisional: some evidence was missing" : "V-RPS"}>
      <span className="font-mono">{score.toFixed(1)}</span>
      <span className="uppercase opacity-80">{priority}</span>
      {provisional && <span title="provisional">~</span>}
    </Badge>
  );
  if (!urgent) return badge;
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {badge}
      <UrgentBadge />
    </span>
  );
}

// Known-exploited (CISA KEV) findings need a prompt decision whatever their score.
export function UrgentBadge() {
  return (
    <Badge tone="red" title="Listed in CISA KEV (known exploited) - review urgently regardless of the score">
      <Siren className="h-3 w-3" />Urgent review
    </Badge>
  );
}

export function ExploitBadge({ vuln }) {
  if (vuln.in_kev) return <Badge tone="red">CISA KEV</Badge>;
  if (vuln.epss != null) return <Badge tone="slate"><span className="font-mono">EPSS {(vuln.epss * 100).toFixed(1)}%</span></Badge>;
  return <Badge tone="slate" title="No exploitation evidence available - not proof of safety">unknown</Badge>;
}

export function SimulatedBadge() {
  return <Badge tone="violet"><FlaskConical className="h-3 w-3" />Simulated</Badge>;
}

// Distinguishes the evidence level of a result everywhere in the UI.
export function EvidenceBadge({ kind }) {
  const map = {
    confirmed: ["green", "Confirmed advisory match", "Version confirmed inside the advisory's affected range"],
    osv_reported: ["teal", "OSV-reported match", "OSV.dev matched this exact version; local range check inconclusive"],
    simulated: ["violet", "Simulated", "Synthetic demo data - not a real vulnerability"],
    potential: ["amber", "Potential exposure", "Inferred from public assets - not confirmed"],
    technology: ["sky", "Technology detected", "Observed in public headers or markup"],
  };
  const [tone, text, title] = map[kind];
  return <Badge tone={tone} title={title}>{text}</Badge>;
}

export function evidenceKind(vuln) {
  if (vuln.synthetic) return "simulated";
  return vuln.match_basis === "local_range_check" ? "confirmed" : "osv_reported";
}

export function ScanStatusBadge({ status }) {
  const map = {
    completed: ["green", "Completed"],
    completed_with_gaps: ["amber", "Completed with gaps"],
    verification_failed: ["red", "Verification failed"],
  };
  const [tone, text] = map[status] ?? ["slate", status];
  return <Badge tone={tone}>{text}</Badge>;
}

export function RemediationBadge({ status }) {
  const map = {
    open: ["slate", "Open"],
    under_review: ["amber", "Under review"],
    resolved_reported: ["teal", "Resolved (user-reported)"],
    verified_by_rescan: ["green", "Verified by re-scan"],
    still_detected: ["red", "Still detected"],
  };
  const [tone, text] = map[status] ?? ["slate", status];
  return <Badge tone={tone}>{text}</Badge>;
}

// ------------------------------------------------------------------ states

export function EmptyState({ icon: Icon = Inbox, title, children, action }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      <div className="mb-1 rounded-full bg-slate-800/80 p-3 text-slate-400"><Icon className="h-5 w-5" /></div>
      <p className="font-medium text-slate-200">{title}</p>
      {children && <div className="max-w-md text-sm text-slate-400">{children}</div>}
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}

export function Loading({ label = "Loading..." }) {
  return (
    <div className="flex items-center justify-center gap-2 py-14 text-sm text-slate-400">
      <Loader2 className="h-4 w-4 animate-spin text-teal-400" /> {label}
    </div>
  );
}

export function ErrorBox({ children, onRetry, title = "Something went wrong" }) {
  return (
    <div role="alert" className="flex flex-wrap items-start justify-between gap-3 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
      <div className="flex gap-2">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
        <div><span className="font-semibold">{title}. </span>{children}</div>
      </div>
      {onRetry && <Button size="sm" variant="danger" onClick={onRetry}><RefreshCw className="h-3.5 w-3.5" />Retry</Button>}
    </div>
  );
}

export function Notice({ tone = "amber", icon: Icon = AlertTriangle, children, className }) {
  const tones = {
    amber: "border-amber-500/30 bg-amber-500/10 text-amber-100",
    violet: "border-violet-500/30 bg-violet-500/10 text-violet-100",
    red: "border-red-500/30 bg-red-500/10 text-red-100",
    teal: "border-teal-500/30 bg-teal-500/10 text-teal-50",
    slate: "border-slate-700 bg-slate-800/50 text-slate-200",
  };
  return (
    <div className={cn("flex gap-2.5 rounded-xl border px-4 py-3 text-sm", tones[tone], className)}>
      <Icon className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="min-w-0">{children}</div>
    </div>
  );
}

// ------------------------------------------------------------------ widgets

export function CopyButton({ text, label = "Copy" }) {
  const [done, setDone] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setDone(true);
      setTimeout(() => setDone(false), 1500);
    } catch {
      setDone(false);
    }
  }
  return (
    <Button size="sm" variant="ghost" onClick={copy} aria-label={`${label}: ${text}`}>
      {done ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
      {done ? "Copied" : label}
    </Button>
  );
}

export function Modal({ open, onClose, title, children, footer, wide }) {
  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-50 flex items-end justify-center bg-slate-950/70 p-0 backdrop-blur-sm sm:items-center sm:p-6"
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          onMouseDown={(e) => e.target === e.currentTarget && onClose()}
        >
          <motion.div
            role="dialog" aria-modal="true" aria-label={title}
            initial={{ y: 12, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 12, opacity: 0 }}
            transition={{ duration: 0.15 }}
            className={cn("flex max-h-[90vh] w-full flex-col rounded-t-2xl border border-slate-800 bg-slate-900 shadow-2xl sm:rounded-2xl", wide ? "sm:max-w-3xl" : "sm:max-w-lg")}
          >
            <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
              <h3 className="text-sm font-semibold text-white">{title}</h3>
              <button onClick={onClose} className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-white" aria-label="Close"><X className="h-4 w-4" /></button>
            </div>
            <div className="overflow-y-auto px-5 py-4 text-sm text-slate-300">{children}</div>
            {footer && <div className="flex flex-wrap justify-end gap-2 border-t border-slate-800 px-5 py-3">{footer}</div>}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

// Choose which dependency scan the Findings / Graph / Remediation pages show.
export function ScanPicker() {
  const { scans, currentScanId, setCurrentScanId } = useApp();
  const deps = scans.filter((s) => s.kind === "dependency");
  if (!deps.length) return null;
  return (
    <label className="flex items-center gap-2 text-xs text-slate-400">
      <span className="hidden sm:inline">Scan</span>
      <select
        value={currentScanId ?? ""}
        onChange={(e) => setCurrentScanId(e.target.value)}
        className="h-9 max-w-[260px] truncate rounded-lg border border-slate-700 bg-slate-900 px-2 text-sm text-slate-200 focus:border-teal-500 focus:outline-none"
      >
        {deps.map((s) => (
          <option key={s.scan_id} value={s.scan_id}>
            {s.mode === "demo" ? "[Demo] " : ""}{s.label}{s.branch ? `@${s.branch}` : ""} - {formatDate(s.created_at)}
          </option>
        ))}
      </select>
    </label>
  );
}

export function Field({ label, hint, children }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-xs font-medium text-slate-300">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-slate-500">{hint}</span>}
    </label>
  );
}

const inputBase =
  "h-10 w-full rounded-lg border bg-slate-950 px-3 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-1";
export const inputClass = `${inputBase} border-slate-700 focus:border-teal-500 focus:ring-teal-500/40`;
export const inputErrorClass = `${inputBase} border-red-500/60 focus:border-red-400 focus:ring-red-500/40`;

// Input with an action button on its right. The button lines up with the input
// (not the hint), and the hint or error sits directly under the input's left edge.
// On narrow screens the order is input, message, then a full-width button.
export function InputAction({ id, label, hint, error, action, ...inputProps }) {
  const msgId = `${id}-msg`;
  return (
    <div>
      <label htmlFor={id} className="mb-1.5 block text-xs font-medium text-slate-300">{label}</label>
      <div className="grid gap-x-3 gap-y-1.5 sm:grid-cols-[minmax(0,1fr)_auto]">
        <input
          id={id}
          className={cn(error ? inputErrorClass : inputClass, "sm:col-start-1 sm:row-start-1")}
          aria-invalid={error ? true : undefined}
          aria-describedby={error || hint ? msgId : undefined}
          {...inputProps}
        />
        {error ? (
          <p id={msgId} role="alert" className="flex items-start gap-1.5 text-xs leading-5 text-red-300 sm:col-start-1 sm:row-start-2">
            <AlertTriangle className="mt-[3px] h-3.5 w-3.5 shrink-0" />
            <span className="min-w-0 break-words">{error}</span>
          </p>
        ) : hint ? (
          <p id={msgId} className="text-xs leading-5 text-slate-500 sm:col-start-1 sm:row-start-2">{hint}</p>
        ) : null}
        <div className="mt-1.5 sm:col-start-2 sm:row-start-1 sm:mt-0 [&>button]:w-full sm:[&>button]:w-auto sm:[&>button]:min-w-36">
          {action}
        </div>
      </div>
    </div>
  );
}
