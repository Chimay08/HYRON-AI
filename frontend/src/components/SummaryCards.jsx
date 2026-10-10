import { cn } from "./ui.jsx";

export function StatCard({ label, value, sub, icon: Icon, tone = "slate", badge, loading }) {
  const tones = {
    red: "text-red-300",
    orange: "text-orange-300",
    amber: "text-amber-300",
    teal: "text-teal-300",
    green: "text-emerald-300",
    slate: "text-white",
  };
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="flex items-start justify-between gap-2">
        <p className="font-mono text-[10px] font-medium uppercase tracking-[0.08em] text-slate-400">{label}</p>
        {Icon && <Icon className="h-4 w-4 text-slate-500" />}
      </div>
      {loading ? (
        <div className="mt-3 h-8 w-16 animate-pulse rounded bg-slate-800" />
      ) : (
        <p className={cn("mt-2 font-mono text-2xl font-semibold tabular-nums tracking-tight", tones[tone])}>{value ?? "-"}</p>
      )}
      <div className="mt-1 flex flex-wrap items-center gap-1.5 text-xs text-slate-500">
        {badge}
        <span>{sub}</span>
      </div>
    </div>
  );
}

export default function SummaryCards({ items, loading }) {
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
      {items.map((item) => <StatCard key={item.label} loading={loading} {...item} />)}
    </div>
  );
}
