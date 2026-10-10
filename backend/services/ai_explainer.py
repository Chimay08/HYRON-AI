"""AI Security Copilot: explanations grounded in verified scan results.

Deterministic, template-based explanations are always available. If
ANTHROPIC_API_KEY is configured, Claude can write the explanation instead,
using ONLY the structured scan data as its source of truth. Only finding
metadata (package names, versions, advisory IDs, scores, project names) is
sent - never source code or uploaded files. Data from private repositories
is not sent unless HYRON_AI_ALLOW_PRIVATE_DATA=1.
"""

from __future__ import annotations

import json
import os

from schemas.scan_result import ExplainResponse, Finding, ScanReport

DEFAULT_MODEL = "claude-opus-5-5"

SYSTEM_PROMPT = (
    "You are HYRON AI's security copilot. You explain software supply-chain scan results to engineers. "
    "The JSON you receive is the ONLY source of truth: never invent CVEs, advisories, versions, exploit "
    "activity, compatibility guarantees or fixes that are not in it. If a field is null or unknown, say the "
    "evidence is incomplete. Projects are 'potentially affected': reachability in a dependency graph does "
    "not prove exploitability. V-RPS is a project heuristic, not an industry standard. "
    "If the data is marked simulated/synthetic, say clearly that it is demo data. Use concise Markdown "
    "with these headings: What it means, Who may be affected, Why it is prioritised, Supported fix, "
    "Compatibility checks, Verify before deploying. Under 350 words."
)


# ---------------------------------------------------------- deterministic --

def _exploit_text(f: Finding) -> str:
    r = f.max_risk.factors
    if r.exploit_source == "cisa_kev":
        return "listed in CISA KEV (known exploited in the wild)"
    if r.exploit_source == "epss":
        return f"EPSS exploitation probability {r.exploit_signal:.1%} over the next 30 days"
    return "no exploitation evidence available (unknown, not proof of safety)"


def explain_finding(f: Finding) -> str:
    v = f.vulnerability
    r = f.max_risk.factors
    sev = f"CVSS {r.cvss}" + {"vector": "", "severity_label": " (estimated from label)",
                              "unknown": " (placeholder - advisory has no severity)"}[r.cvss_source]
    direct = [a.project for a in f.affected_projects if a.relation == "direct"]
    trans = [a.project for a in f.affected_projects if a.relation == "transitive"]
    reach = []
    if direct:
        reach.append(f"directly by {', '.join(direct)}")
    if trans:
        reach.append(f"transitively by {', '.join(trans)}")
    fix = f"First fixed version per advisory: {v.fixed_version}." if v.fixed_version else "No fixed version is published."
    basis = (
        "Version confirmed inside the advisory's affected range."
        if v.match_basis == "local_range_check"
        else "Reported by OSV.dev for this exact version (local range check inconclusive)."
    )
    caveat = " The version is the lower bound of a declared range; verify the installed version." \
        if f.version_status == "range_min" else ""
    demo = " [SIMULATED DEMO ADVISORY]" if v.synthetic else ""
    return (
        f"{f.package}@{f.version} matches {v.id}{demo}: {v.summary or 'no summary provided'} "
        f"Severity {sev}; {_exploit_text(f)}. Used {' and '.join(reach) or 'by no scanned project'} - "
        f"potentially affected, exploitability not established. "
        f"V-RPS {f.max_risk.score}/100 ({f.max_risk.priority}). {fix} {basis}{caveat}"
    )


def copilot_finding(report: ScanReport, f: Finding) -> str:
    v = f.vulnerability
    step = next((s for s in report.patch_plan if s.step_key == f.package_node), None)
    lines = []
    if v.synthetic:
        lines += ["> **Simulated demo data** - this advisory is fictional.", ""]
    lines += [
        "### What it means",
        f"{f.package}@{f.version} ({f.ecosystem}) matches **{v.id}**"
        + (f" (aliases: {', '.join(v.aliases[:4])})" if v.aliases else "") + f". {v.summary or 'The advisory has no summary.'}",
        "",
        "### Who may be affected",
    ]
    for a in f.affected_projects:
        lines.append(f"- **{a.project}** - {a.relation}, {a.runtime_context} context: {' > '.join(a.path)}")
    if not f.affected_projects:
        lines.append("- No scanned project depends on this package.")
    lines += [
        "",
        "Being reachable in the dependency graph does not prove the vulnerable code is executed.",
        "",
        "### Why it is prioritised",
        f"V-RPS {f.max_risk.score}/100 ({f.max_risk.priority}) = "
        f"0.35({f.max_risk.factors.severity_score}) + 0.30({f.max_risk.factors.exploit_score}) + "
        f"0.20({f.max_risk.factors.exposure_score}) + 0.15({f.max_risk.factors.propagation_score}).",
        f"- Severity: CVSS {f.max_risk.factors.cvss} ({f.max_risk.factors.cvss_source})",
        f"- Exploitability: {_exploit_text(f)}",
        f"- Exposure: {f.exposure.production_projects} production, {f.exposure.development_only_projects} dev-only, "
        f"{f.exposure.unknown_context_projects} unknown-context project(s)",
        f"- Propagation: {f.exposure.affected_projects} distinct affected project(s)",
    ]
    if f.max_risk.missing_data:
        lines.append(f"- Missing evidence: {', '.join(f.max_risk.missing_data)}")
    lines += ["", "### Supported fix"]
    if v.fixed_version:
        lines.append(f"The advisory lists **{v.fixed_version}** as the first fixed version for this range.")
        if step and step.recommended_version and step.recommended_version != v.fixed_version:
            lines.append(f"The remediation plan recommends {step.recommended_version} to cover all advisories on this package.")
    else:
        lines.append("No fixed version is published - mitigate, replace or monitor the advisory.")
    if step and step.upgrade_commands:
        lines += ["", "```", *step.upgrade_commands, "```"]
    lines += ["", "### Compatibility checks"]
    lines += [f"- {c}" for c in (step.checklist if step else [])][:5] or ["- Review the changelog before upgrading."]
    lines += [
        "", "### Verify before deploying",
        "- Regenerate the lockfile and confirm the resolved version.",
        "- Run the test suites of every affected project.",
        "- Re-scan with HYRON AI; only a re-scan marks the fix as verified.",
    ]
    return "\n".join(lines)


def deterministic_summary(report: ScanReport) -> str:
    s = report.summary
    if report.status == "verification_failed":
        return ("The live vulnerability check failed, so no result from this scan is verified. "
                "Retry when OSV.dev is reachable; do not treat the absence of findings as safe.")
    if not report.findings:
        gaps = f" {s.unscanned_packages} package(s) could not be checked." if s.unscanned_packages else ""
        return (
            f"No known vulnerabilities matched the {s.scanned_packages} scanned package version(s).{gaps} "
            "This is not a guarantee of safety: advisories may be missing and unscanned packages are unknown."
        )
    lines = [
        f"{s.vulnerable_packages} vulnerable package(s) potentially affect {s.affected_projects} of "
        f"{s.total_projects} project(s); {s.high_priority_findings} finding(s) are high priority.",
        "",
        "Patch order:",
    ]
    for step in report.patch_plan[:10]:
        target = step.recommended_version or "no known fix"
        lines.append(
            f"{step.order}. {step.package} {step.current_version} -> {target} "
            f"(V-RPS {step.max_risk_score}, {len(step.affected_projects)} project(s))"
        )
    if s.unscanned_packages:
        lines += ["", f"{s.unscanned_packages} package(s) were not scanned - their exposure is unknown."]
    if report.mode == "demo":
        lines += ["", "All findings are SIMULATED demo data, not real advisories."]
    return "\n".join(lines)


# --------------------------------------------------------------------- AI --

def ai_configured() -> bool:
    return bool(os.getenv("ANTHROPIC_API_KEY")) and os.getenv("HYRON_AI_ENABLED", "1") != "0"


def ai_allowed_for(report: ScanReport) -> tuple[bool, str]:
    if not ai_configured():
        return False, "AI copilot disabled (no ANTHROPIC_API_KEY configured) - showing deterministic explanation."
    if report.source.private and os.getenv("HYRON_AI_ALLOW_PRIVATE_DATA", "0") != "1":
        return False, ("Scan comes from a private repository; its dependency data is not sent to an external AI "
                       "service unless HYRON_AI_ALLOW_PRIVATE_DATA=1. Showing deterministic explanation.")
    return True, ""


def _finding_payload(f: Finding) -> dict:
    return {
        "package": f.package, "version": f.version, "ecosystem": f.ecosystem, "version_status": f.version_status,
        "advisory": f.vulnerability.model_dump(include={
            "id", "aliases", "summary", "cvss_score", "cvss_source", "severity_label", "fixed_version",
            "in_kev", "epss", "match_basis", "source", "synthetic",
        }),
        "hyron_risk_score": f.max_risk.score, "priority": f.max_risk.priority,
        "factors": f.max_risk.factors.model_dump(exclude={"formula"}),
        "missing_data": f.max_risk.missing_data,
        "affected_projects": [
            {"project": a.project, "relation": a.relation, "runtime": a.runtime_context, "path": a.path,
             "score": a.risk.score} for a in f.affected_projects[:15]
        ],
    }


def _payload(report: ScanReport, finding: Finding | None) -> str:
    base = {"mode": report.mode, "simulated_data": report.mode == "demo", "scan_status": report.status}
    if finding:
        step = next((s for s in report.patch_plan if s.step_key == finding.package_node), None)
        base["finding"] = _finding_payload(finding)
        base["remediation"] = step.model_dump(include={
            "recommended_version", "fix_status", "warnings", "upgrade_commands", "checklist",
        }) if step else None
    else:
        base["summary"] = report.summary.model_dump()
        base["findings"] = [_finding_payload(f) for f in report.findings[:20]]
        base["patch_plan"] = [s.model_dump(include={
            "order", "package", "current_version", "recommended_version", "fix_status", "warnings",
        }) for s in report.patch_plan[:15]]
        base["coverage_gaps"] = len(report.coverage_gaps)
    return json.dumps(base)


async def explain(report: ScanReport, finding: Finding | None = None) -> ExplainResponse:
    fallback = copilot_finding(report, finding) if finding else deterministic_summary(report)
    fid = finding.finding_id if finding else None
    allowed, why = ai_allowed_for(report)
    if not allowed:
        return ExplainResponse(scan_id=report.scan_id, finding_id=fid, source="deterministic",
                               explanation=fallback, note=why)
    import anthropic

    model = os.getenv("HYRON_AI_MODEL", DEFAULT_MODEL)
    task = "Explain this finding." if finding else "Summarise this scan and the patch order."
    try:
        client = anthropic.AsyncAnthropic(timeout=60.0, max_retries=1)
        resp = await client.beta.messages.create(
            model=model,
            max_tokens=4000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"{task}\n\nVerified scan data (JSON):\n{_payload(report, finding)}"}],
            output_config={"effort": "low"},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
    except anthropic.APIConnectionError:
        note = "AI service unreachable; showing deterministic explanation."
    except anthropic.RateLimitError:
        note = "AI service rate-limited; showing deterministic explanation."
    except anthropic.APIStatusError as exc:
        note = f"AI service returned HTTP {exc.status_code}; showing deterministic explanation."
    else:
        if resp.stop_reason == "refusal":
            note = "AI service declined the request; showing deterministic explanation."
        else:
            text = "".join(b.text for b in resp.content if b.type == "text").strip()
            if text:
                return ExplainResponse(
                    scan_id=report.scan_id, finding_id=fid, source="ai", model=model, explanation=text,
                    note="AI-generated from verified scan data - cross-check against the evidence shown.",
                )
            note = "AI service returned no text; showing deterministic explanation."
    return ExplainResponse(scan_id=report.scan_id, finding_id=fid, source="deterministic",
                           explanation=fallback, note=note)
