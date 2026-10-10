"""Scan orchestration, the in-memory result store and remediation status.

Storage is process memory only: results disappear on restart. Scans are
partitioned by workspace ID (an unguessable per-browser identifier sent in
the X-Workspace-Id header). That isolates casual users from each other but
is NOT authentication - see README "Security".
"""

from __future__ import annotations

import json
import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from schemas.scan_result import (
    AffectedProject, CoverageGap, DataSource, Exposure, Finding, GraphData, GraphEdge, GraphNode,
    ParseIssue, Project, ResolvedItem, ScanListItem, ScanReport, ScanSource, ScanSummary, WebsiteReport,
)
from services import ai_explainer, dependency_graph as dg
from services.patch_planner import build_patch_plan
from services.risk_engine import SCORE_NAME, score_vulnerability
from services.vulnerability_scanner import PackageRef, ScanOutcome, scan_demo, scan_live

SAMPLE_DIR = Path(__file__).resolve().parents[2] / "sample_data"
DEMO_FILE = SAMPLE_DIR / "demo_dependencies.json"
MAX_SCANS_PER_WORKSPACE = 50
MAX_SCANS_TOTAL = 1000

DEMO_NOTICE = (
    "DEMO DATA - SIMULATED. All packages (@hyron-demo/*), advisories (HYRON-DEMO-*), KEV and EPSS values "
    "are synthetic. They are not real vulnerabilities and were not verified against any live source."
)
LIVE_NOTICE = (
    "Live scan - advisories from OSV.dev, exploitation evidence from CISA KEV and FIRST EPSS when available. "
    "Projects reachable from a vulnerable package are potentially affected; exploitability is not established."
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------------------------ store --

@dataclass
class Entry:
    workspace: str
    source_key: str
    report: ScanReport | WebsiteReport
    graph: GraphData | None


class ScanStore:
    def __init__(self) -> None:
        self._items: OrderedDict[tuple[str, str], Entry] = OrderedDict()
        self._status: dict[tuple[str, str, str], dict] = {}
        self._lock = threading.Lock()

    def put(self, entry: Entry) -> None:
        with self._lock:
            self._items[(entry.workspace, entry.report.scan_id)] = entry
            mine = [k for k in self._items if k[0] == entry.workspace]
            for k in mine[: max(0, len(mine) - MAX_SCANS_PER_WORKSPACE)]:
                del self._items[k]
            while len(self._items) > MAX_SCANS_TOTAL:
                self._items.popitem(last=False)

    def get(self, workspace: str, scan_id: str) -> Entry | None:
        return self._items.get((workspace, scan_id))

    def list(self, workspace: str) -> list[Entry]:
        return [e for (ws, _), e in reversed(self._items.items()) if ws == workspace]

    def latest_dependency_scan(self, workspace: str, source_key: str) -> ScanReport | None:
        for e in self.list(workspace):
            if e.source_key == source_key and isinstance(e.report, ScanReport):
                return e.report
        return None

    # remediation status, keyed per workspace + source so it survives re-scans
    def get_status(self, workspace: str, source_key: str, step_key: str) -> dict | None:
        return self._status.get((workspace, source_key, step_key))

    def set_status(self, workspace: str, source_key: str, step_key: str, status: str, note: str = "") -> dict:
        value = {"status": status, "note": note, "updated_at": now()}
        self._status[(workspace, source_key, step_key)] = value
        return value

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
            self._status.clear()


STORE = ScanStore()


def list_items(workspace: str) -> list[ScanListItem]:
    out = []
    for e in STORE.list(workspace):
        r = e.report
        if isinstance(r, ScanReport):
            out.append(ScanListItem(
                scan_id=r.scan_id, kind="dependency", created_at=r.created_at, mode=r.mode, status=r.status,
                source_type=r.source.type, label=r.source.label, url=r.source.url, branch=r.source.branch,
                summary=r.summary,
            ))
        else:
            out.append(ScanListItem(
                scan_id=r.scan_id, kind="website", created_at=r.created_at, mode="live", status=r.status,
                source_type="website", label=r.final_url, url=r.url,
                website_counts={"technologies": len(r.technologies), "potential_exposures": len(r.potential_exposures)},
            ))
    return out


def load_demo_data() -> dict:
    return json.loads(DEMO_FILE.read_text(encoding="utf-8"))


def _dedupe_project_names(projects: list[Project]) -> None:
    # Project names become graph node IDs, so two projects must never share one -
    # including a renamed "app-2" colliding with a project literally called "app-2".
    taken = {p.name for p in projects}
    used: set[str] = set()
    for p in projects:
        if p.name in used:
            n = 2
            while f"{p.name}-{n}" in taken or f"{p.name}-{n}" in used:
                n += 1
            p.name = f"{p.name}-{n}"
        used.add(p.name)


def store_website_report(workspace: str, report: WebsiteReport) -> None:
    STORE.put(Entry(workspace=workspace, source_key=f"web:{report.final_url}", report=report, graph=None))


# ------------------------------------------------------------------- scan --

async def run_scan(
    projects: list[Project], *, mode: str, source: ScanSource, workspace: str = "default",
    parse_issues: list[ParseIssue] | None = None, demo_data: dict | None = None,
    extra_sources: list[DataSource] | None = None,
) -> tuple[ScanReport, GraphData]:
    _dedupe_project_names(projects)
    g = dg.build_graph(projects)
    warnings: list[str] = []

    refs: list[PackageRef] = []
    gaps: list[CoverageGap] = []
    unchecked: set[str] = set()
    for node, data in g.nodes(data=True):
        if data["type"] != "package":
            continue
        if data["version_status"] == "unresolved" or not str(data["version"] or "").strip():
            # Never query OSV without a concrete version: it would return every advisory.
            unchecked.add(node)
            gaps.append(CoverageGap(
                package=data["name"], ecosystem=data["ecosystem"], declared=data.get("declared"),
                reason="No concrete version could be derived from the declared constraint",
            ))
        else:
            refs.append(PackageRef(node, data["ecosystem"], data["name"], data["version"]))

    outcome: ScanOutcome = scan_demo(refs, demo_data or {}) if mode == "demo" else await scan_live(refs)
    warnings += outcome.warnings
    for node_id, reason in outcome.errors.items():
        d = g.nodes[node_id]
        gaps.append(CoverageGap(package=d["name"], ecosystem=d["ecosystem"], declared=d.get("declared"), reason=reason))

    manifest_only = [p for p in projects if not p.has_transitive_data]
    for p in manifest_only:
        warnings.append(
            f"{p.name} ({p.source_file}): manifest lists direct dependencies only - transitive dependencies "
            "were not analysed. Add the lockfile for a complete graph."
        )
    if any(d.get("version_status") == "range_min" for _, d in g.nodes(data=True)):
        warnings.append(
            "Some versions are lower bounds of declared ranges (e.g. ^1.2.0); results describe that version, "
            "not necessarily what is installed."
        )
    inferred_edges = sum(1 for _, _, e in g.edges(data=True) if e.get("inferred"))

    # ---- findings
    findings: list[Finding] = []
    entries: dict[tuple[str, str], dict] = {}
    for node_id, matches in outcome.matches.items():
        impacts = dg.blast_radius(g, node_id)
        d = g.nodes[node_id]
        for m in matches:
            entries[(node_id, m.info.id)] = m.affected_entry
            affected = [
                AffectedProject(
                    project=g.nodes[i.project]["name"], relation=i.relation,
                    path=[dg.label(g, n) for n in i.path], runtime_context=i.runtime_context,
                    inferred_link=i.inferred_link,
                    risk=score_vulnerability(m.info, i.runtime_context, len(impacts)),
                )
                for i in impacts
            ]
            affected.sort(key=lambda a: (-a.risk.score, a.project))
            max_risk = affected[0].risk if affected else score_vulnerability(m.info, "unknown", 0)
            exposure = Exposure(
                affected_projects=len(affected),
                production_projects=sum(a.runtime_context == "production" for a in affected),
                development_only_projects=sum(a.runtime_context == "development" for a in affected),
                unknown_context_projects=sum(a.runtime_context == "unknown" for a in affected),
                direct_dependents=sum(a.relation == "direct" for a in affected),
                transitive_dependents=sum(a.relation == "transitive" for a in affected),
            )
            f = Finding(
                finding_id=f"{node_id}|{m.info.id}", package_node=node_id, package=d["name"],
                ecosystem=d["ecosystem"], version=d["version"], version_status=d["version_status"],
                vulnerability=m.info, max_risk=max_risk, exposure=exposure, affected_projects=affected,
            )
            f.explanation = ai_explainer.explain_finding(f)
            findings.append(f)
    findings.sort(key=lambda f: (-f.max_risk.score, f.package, f.vulnerability.id))

    plan = build_patch_plan(findings, g, entries)

    # ---- status
    if mode == "live" and refs and len(outcome.errors) >= len(refs):
        status = "verification_failed"
        detail = ("The live vulnerability check failed for every package. No result from this scan is "
                  "verified - do NOT treat it as clean. Retry when OSV.dev is reachable.")
    elif outcome.errors or gaps:
        status = "completed_with_gaps"
        detail = f"Completed, but {len(gaps)} package(s) could not be checked - their exposure is unknown."
    else:
        status = "completed"
        detail = "All resolvable package versions were checked." if mode == "live" else \
            "Demo scan completed with simulated data."

    # ---- graph payload
    vulnerable = set(outcome.matches)
    affected_nodes = dg.potentially_affected_nodes(g, vulnerable)
    depths = dg.depths_from_projects(g)
    node_vulns: dict[str, list[str]] = {}
    node_score: dict[str, float] = {}
    node_prio: dict[str, str] = {}
    node_sev: dict[str, str] = {}
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}
    for f in findings:
        node_vulns.setdefault(f.package_node, []).append(f.vulnerability.id)
        sev = f.vulnerability.severity_label or "UNKNOWN"
        if sev_rank.get(sev, 0) >= sev_rank.get(node_sev.get(f.package_node, "UNKNOWN"), 0):
            node_sev[f.package_node] = sev
        if f.max_risk.score >= node_score.get(f.package_node, -1):
            node_score[f.package_node] = f.max_risk.score
            node_prio[f.package_node] = f.max_risk.priority
        for ap in f.affected_projects:
            pid = dg.project_node(ap.project)
            if ap.risk.score >= node_score.get(pid, -1):
                node_score[pid] = ap.risk.score
                node_prio[pid] = ap.risk.priority

    scan_id = uuid.uuid4().hex[:12]
    nodes = []
    for n, d in g.nodes(data=True):
        if n in vulnerable:
            st = "vulnerable"
        elif n in affected_nodes:
            st = "affected"
        elif d["type"] == "package" and (n in unchecked or n in outcome.errors):
            st = "unscanned"
        else:
            st = "clean"
        nodes.append(GraphNode(
            id=n, label=dg.label(g, n), type=d["type"], status=st,
            ecosystem=d.get("ecosystem"), version=d.get("version"), version_status=d.get("version_status"),
            depth=depths.get(n), vulnerabilities=node_vulns.get(n, []),
            max_risk_score=node_score.get(n), priority=node_prio.get(n), severity=node_sev.get(n),
        ))
    edges = [GraphEdge(source=u, target=v, scope=e["scope"], inferred=bool(e.get("inferred")))
             for u, v, e in g.edges(data=True)]
    incomplete_reasons = []
    if manifest_only:
        incomplete_reasons.append(f"{len(manifest_only)} project(s) were analysed from manifests without lockfiles, "
                                  "so transitive dependencies are missing")
    if gaps:
        incomplete_reasons.append(f"{len(gaps)} package(s) could not be version-checked")
    if inferred_edges:
        incomplete_reasons.append(f"{inferred_edges} link(s) were inferred rather than stated by a manifest")
    graph = GraphData(
        scan_id=scan_id, complete=not incomplete_reasons,
        completeness_note=("Graph built from resolved dependency data; every edge comes from the input."
                           if not incomplete_reasons else "Incomplete: " + "; ".join(incomplete_reasons) + "."),
        nodes=nodes, edges=edges,
    )

    # ---- summary
    sev_counts: dict[str, int] = {}
    prio_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        key = f.vulnerability.severity_label or "UNKNOWN"
        key = "LOW" if key == "NONE" else key
        sev_counts[key] = sev_counts.get(key, 0) + 1
        prio_counts[f.max_risk.priority] += 1
    pkg_nodes = [n for n, d in g.nodes(data=True) if d["type"] == "package"]
    direct_pkgs = {v for u, v in g.edges() if g.nodes[u]["type"] == "project"}
    summary = ScanSummary(
        total_projects=len(projects),
        total_packages=len(pkg_nodes),
        scanned_packages=len(refs) - len(outcome.errors),
        unscanned_packages=len(gaps),
        vulnerable_packages=len(vulnerable),
        affected_projects=len({ap.project for f in findings for ap in f.affected_projects}),
        high_priority_findings=prio_counts["critical"] + prio_counts["high"],
        total_findings=len(findings),
        direct_packages=len(direct_pkgs),
        transitive_packages=len(pkg_nodes) - len(direct_pkgs),
        severity_counts=sev_counts, priority_counts=prio_counts,
        total_risk=round(sum(f.max_risk.score for f in findings), 1),
    )

    limitations = [
        "'Potentially affected' means reachable in the dependency graph; code-level reachability and "
        "exploitability were not analysed.",
        f"The {SCORE_NAME} is a HYRON-specific prioritisation heuristic, not an industry-standard score.",
        "Fixed versions come from advisory data; upgrade compatibility was not tested.",
        "Results are held in server memory and are lost when the backend restarts.",
    ]
    if manifest_only:
        limitations.insert(0, f"{len(manifest_only)} project(s) lack lockfile data: transitive coverage is incomplete.")
    if mode == "demo":
        limitations.insert(0, "All findings are SIMULATED demo data and must not be reported as real vulnerabilities.")

    # ---- re-scan verification & remediation status
    source_key = _source_key(source)
    previous = STORE.latest_dependency_scan(workspace, source_key)
    resolved: list[ResolvedItem] = []
    current_keys = {s.step_key for s in plan}
    if previous and status != "verification_failed" and previous.status != "verification_failed":
        errored_nodes = set(outcome.errors)
        for step in previous.patch_plan:
            node_id = step.step_key
            if step.step_key in current_keys or node_id in errored_nodes:
                continue
            resolved.append(ResolvedItem(
                step_key=step.step_key, package=step.package, version=step.current_version,
                vulnerabilities=step.vulnerabilities, previous_scan_id=previous.scan_id,
            ))
            STORE.set_status(workspace, source_key, step.step_key, "verified_by_rescan",
                             f"Not detected by re-scan {scan_id}")
    for step in plan:
        saved = STORE.get_status(workspace, source_key, step.step_key)
        if not saved:
            continue
        if saved["status"] in ("resolved_reported", "verified_by_rescan"):
            step.remediation_status = "still_detected"
            step.status_note = f"Marked resolved on {saved['updated_at']}, but this scan still detects it."
            step.status_updated_at = now()
        else:
            step.remediation_status = saved["status"]
            step.status_note = saved["note"]
            step.status_updated_at = saved["updated_at"]

    report = ScanReport(
        scan_id=scan_id, created_at=now(), mode=mode, status=status, status_detail=detail,
        data_notice=DEMO_NOTICE if mode == "demo" else LIVE_NOTICE, source=source,
        summary=summary, projects=[p.name for p in projects], findings=findings,
        patch_plan=plan, coverage_gaps=gaps, warnings=warnings, limitations=limitations,
        data_sources=(extra_sources or []) + outcome.sources, parse_issues=parse_issues or [],
        resolved_since_previous=resolved, previous_scan_id=previous.scan_id if previous else None,
    )
    STORE.put(Entry(workspace=workspace, source_key=source_key, report=report, graph=graph))
    return report, graph


def _source_key(source: ScanSource) -> str:
    if source.type == "repository":
        return f"github:{source.label}@{source.branch}"
    if source.type == "demo":
        return "demo"
    return "upload:" + "+".join(sorted(source.files))


def update_step_status(workspace: str, report: ScanReport, step_key: str, status: str, note: str):
    step = next((s for s in report.patch_plan if s.step_key == step_key), None)
    if step is None:
        return None
    saved = STORE.set_status(workspace, _source_key(report.source), step_key, status, note)
    step.remediation_status = status
    step.status_note = note or ("Reported resolved by a user - not verified until a re-scan confirms it."
                                if status == "resolved_reported" else "")
    step.status_updated_at = saved["updated_at"]
    return step
