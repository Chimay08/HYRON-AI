import re

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from schemas.scan_result import (
    ExplainRequest, ExplainResponse, PatchStep, PRDraft, PRDraftRequest, ScanReport, StatusUpdate, WebsiteReport,
)
from services import ai_explainer
from services.pipeline import STORE, Entry, update_step_status
from services.security import ai_rate_limit, workspace_id

router = APIRouter(prefix="/api", tags=["reports"])


def _entry(workspace: str, scan_id: str) -> Entry:
    entry = STORE.get(workspace, scan_id)
    if entry is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found (results are kept in memory and lost on restart)")
    return entry


def _dependency_report(workspace: str, scan_id: str) -> ScanReport:
    report = _entry(workspace, scan_id).report
    if not isinstance(report, ScanReport):
        raise HTTPException(status.HTTP_409_CONFLICT, "This operation needs a dependency scan, not a website inspection")
    return report


def _step(report: ScanReport, step_key: str) -> PatchStep:
    step = next((s for s in report.patch_plan if s.step_key == step_key), None)
    if step is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Remediation step not found in this scan")
    return step


@router.get("/reports/{scan_id}", response_model=ScanReport | WebsiteReport)
async def get_report(scan_id: str, workspace: str = Depends(workspace_id)):
    """Full report: summary, findings with evidence, dependency paths, risk breakdown, remediation plan,
    data sources with timestamps, coverage gaps and limitations. Website scans return a WebsiteReport."""
    return _entry(workspace, scan_id).report


@router.get("/reports/{scan_id}/export")
async def export_report(scan_id: str, workspace: str = Depends(workspace_id)):
    """Download the report as a JSON file."""
    report = _entry(workspace, scan_id).report
    return JSONResponse(
        content=report.model_dump(mode="json"),
        headers={"Content-Disposition": f'attachment; filename="hyron-report-{report.scan_id}.json"'},
    )


@router.post("/reports/{scan_id}/explain", response_model=ExplainResponse)
async def explain(request: Request, scan_id: str, body: ExplainRequest | None = None,
                  workspace: str = Depends(workspace_id)):
    """AI Security Copilot. Explains one finding (finding_id) or the whole scan.

    Uses Claude when ANTHROPIC_API_KEY is configured; otherwise a deterministic explanation built from the
    verified scan data. Private-repository data is not sent to the AI service unless explicitly allowed.
    AI calls are rate limited per client (HYRON_AI_RATE_LIMIT per HYRON_AI_RATE_WINDOW seconds)."""
    report = _dependency_report(workspace, scan_id)
    if ai_explainer.ai_allowed_for(report)[0]:
        ai_rate_limit(request)
    finding = None
    if body and body.finding_id:
        finding = next((f for f in report.findings if f.finding_id == body.finding_id), None)
        if finding is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found in this scan")
    return await ai_explainer.explain(report, finding)


@router.post("/reports/{scan_id}/remediation/status", response_model=PatchStep)
async def set_remediation_status(scan_id: str, body: StatusUpdate, workspace: str = Depends(workspace_id)):
    """Track remediation: open, under_review, or resolved_reported (user-reported; requires confirm=true).

    'verified_by_rescan' can only be set by a later scan of the same source that no longer detects the issue."""
    report = _dependency_report(workspace, scan_id)
    _step(report, body.step_key)
    if body.status == "resolved_reported" and not body.confirm:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Confirm (confirm=true) that the fix was applied")
    return update_step_status(workspace, report, body.step_key, body.status, body.note)


@router.post("/reports/{scan_id}/remediation/pr-draft", response_model=PRDraft)
async def pr_draft(scan_id: str, body: PRDraftRequest, workspace: str = Depends(workspace_id)):
    """Prepare (not open) a pull-request description for one remediation step.

    HYRON AI never pushes, merges or deploys. Apply the suggested changes on a branch and open the PR yourself."""
    report = _dependency_report(workspace, scan_id)
    step = _step(report, body.step_key)
    if not step.recommended_version:
        raise HTTPException(status.HTTP_409_CONFLICT, "No verified fixed version exists for this package")
    slug = re.sub(r"[^a-z0-9]+", "-", step.package.lower()).strip("-")
    branch = f"hyron/upgrade-{slug}-{step.recommended_version}"
    simulated = "\n> **Simulated demo data - do not open this PR against a real repository.**\n" if report.mode == "demo" else ""
    advisories = "\n".join(
        f"- [{v}]({u})" if u else f"- {v}"
        for v, u in zip(step.vulnerabilities, step.advisory_urls + [None] * len(step.vulnerabilities))
    )
    body_md = "\n".join([
        f"## Upgrade `{step.package}` {step.current_version} -> {step.recommended_version}",
        simulated,
        step.rationale,
        "",
        "### Advisories", advisories,
        "",
        f"**V-RPS:** {step.max_risk_score} ({step.priority}) - project heuristic, not a standard.",
        "",
        "### Affected projects", *[f"- {p}" for p in step.affected_projects],
        "",
        "### Changes", *[f"- {a}" for a in step.actions],
        "",
        "### Commands", "```", *step.upgrade_commands, "```",
        "",
        "### Warnings", *([f"- {w}" for w in step.warnings] or ["- none"]),
        "",
        "### Test checklist", *[f"- [ ] {c}" for c in step.checklist],
        "",
        "_Prepared by HYRON AI from advisory data. Compatibility is not verified; do not merge without review "
        "and passing tests._",
    ])
    compare = None
    if report.source.type == "repository" and report.source.url and report.source.branch:
        compare = f"{report.source.url}/compare/{report.source.branch}...{branch}?expand=1"
    return PRDraft(
        title=f"chore(deps): upgrade {step.package} to {step.recommended_version} ({', '.join(step.vulnerabilities[:3])})",
        branch=branch, body=body_md, suggested_changes=step.actions, compare_url=compare,
        note="Draft only. Push the branch with these changes, then use the compare link to open the PR for review.",
    )
