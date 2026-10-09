import { Link } from "react-router-dom";
import { FlaskConical, OctagonAlert, TriangleAlert } from "lucide-react";
import { Notice, ScanStatusBadge, formatDate } from "./ui.jsx";

// Always-visible context for a dependency scan: what was scanned, whether
// the data is simulated, and whether verification was complete.
export default function ScanBanner({ report, compact }) {
  const src = report.source;
  return (
    <div className="space-y-3">
      {!compact && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400">
          <ScanStatusBadge status={report.status} />
          <span className="text-slate-200">{src.label}{src.branch ? `@${src.branch}` : ""}</span>
          {src.commit && <span className="font-mono">{src.commit.slice(0, 10)}</span>}
          <span>{formatDate(report.created_at)}</span>
          <Link to={`/reports/${report.scan_id}`} className="text-teal-300 hover:underline">Full report</Link>
        </div>
      )}
      {report.mode === "demo" && (
        <Notice tone="violet" icon={FlaskConical}><strong>Simulated demo data.</strong> {report.data_notice}</Notice>
      )}
      {report.status === "verification_failed" && (
        <Notice tone="red" icon={OctagonAlert}><strong>Live verification failed.</strong> {report.status_detail}</Notice>
      )}
      {report.status === "completed_with_gaps" && (
        <Notice tone="amber" icon={TriangleAlert}>
          {report.status_detail}{" "}
          <Link to={`/reports/${report.scan_id}#coverage`} className="underline">See coverage gaps</Link>
        </Notice>
      )}
    </div>
  );
}
