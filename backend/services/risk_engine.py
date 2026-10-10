"""V-RPS - HYRON's transparent remediation-priority heuristic (not a standard).

    V-RPS = 0.35S + 0.30E + 0.20X + 0.15P

All four normalized 0-100 inputs are reported separately:

Severity (CVSS)
    From the advisory's CVSS v3 vector. If only a qualitative label exists
    (e.g. GHSA "HIGH"), the band mid-point is used and flagged. If nothing
    exists, UNKNOWN_CVSS is used, the score is marked provisional and the
    gap is listed in `missing_data`.
Exploitability (E)
    100 when listed in CISA KEV, otherwise FIRST EPSS probability x 100.
    Missing evidence uses a disclosed neutral placeholder of 50.
Exposure (X)
    100 for production, 40 for development-only, and a disclosed neutral
    placeholder of 50 when the dependency context is unknown.
Propagation (P)
    20 points per distinct affected project, capped at 100 (five projects).

All weights live here and nowhere else.
"""

from __future__ import annotations

from schemas.scan_result import RiskFactors, RiskScore
from schemas.vulnerability import VulnerabilityInfo

SCORE_NAME = "V-RPS"
FORMULA = "0.35S + 0.30E + 0.20X + 0.15P"

KEV_SIGNAL = 1.0
UNKNOWN_EXPLOIT_SIGNAL = 0.5
UNKNOWN_CVSS = 5.0
RUNTIME_FACTORS = {"production": 1.0, "development": 0.4, "unknown": 0.5}
PROPAGATION_POINTS_PER_PROJECT = 20.0

CRITICAL_THRESHOLD = 80.0
HIGH_THRESHOLD = 60.0
MEDIUM_THRESHOLD = 35.0


def describe() -> dict:
    """Machine-readable description of the heuristic, served by the API."""
    return {
        "name": SCORE_NAME,
        "formula": FORMULA,
        "standard": False,
        "weights": {
            "severity": 0.35, "exploit_evidence": 0.30, "exposure": 0.20, "propagation": 0.15,
            "kev_signal": KEV_SIGNAL,
            "runtime_factors": RUNTIME_FACTORS,
            "propagation_points_per_project": PROPAGATION_POINTS_PER_PROJECT,
        },
        "fallbacks": {
            "cvss_unknown": UNKNOWN_CVSS, "exploit_unknown": UNKNOWN_EXPLOIT_SIGNAL,
            "runtime_unknown": RUNTIME_FACTORS["unknown"],
        },
        "priority_thresholds": {"critical": CRITICAL_THRESHOLD, "high": HIGH_THRESHOLD, "medium": MEDIUM_THRESHOLD},
        "urgent_review": "Any finding listed in CISA KEV is flagged for urgent review, independent of its score",
    }


def risk_formula(cvss: float, exploit_signal: float, runtime_factor: float, affected_projects: int = 1) -> float:
    s = max(0.0, min(100.0, cvss * 10))
    e = max(0.0, min(100.0, exploit_signal * 100))
    x = max(0.0, min(100.0, runtime_factor * 100))
    p = max(0.0, min(100.0, affected_projects * PROPAGATION_POINTS_PER_PROJECT))
    return round(0.35 * s + 0.30 * e + 0.20 * x + 0.15 * p, 1)


def priority_for(score: float) -> str:
    if score >= CRITICAL_THRESHOLD:
        return "critical"
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def score_vulnerability(vuln: VulnerabilityInfo, runtime_context: str, affected_projects: int = 1) -> RiskScore:
    notes: list[str] = []
    missing: list[str] = []
    provisional = False

    if vuln.cvss_score is not None:
        cvss = vuln.cvss_score
        if vuln.cvss_source == "severity_label":
            notes.append(f"CVSS estimated from severity label '{vuln.severity_label}' (no v3 vector in advisory)")
    else:
        cvss = UNKNOWN_CVSS
        provisional = True
        missing.append("cvss")
        notes.append(f"No severity in advisory: placeholder CVSS {UNKNOWN_CVSS} used - score is provisional")

    if vuln.in_kev:
        signal, source = KEV_SIGNAL, "cisa_kev"
        notes.append("Listed in CISA KEV (known exploited): flagged for urgent review regardless of score")
    elif vuln.epss is not None:
        signal, source = vuln.epss, "epss"
    else:
        signal, source = UNKNOWN_EXPLOIT_SIGNAL, "unknown"
        provisional = True
        missing.append("exploit_evidence")
        if vuln.in_kev is None:
            notes.append("Exploit evidence unavailable (KEV/EPSS not retrieved) - not evidence of safety")
        else:
            notes.append("Not in CISA KEV and no EPSS score - exploit likelihood unknown")

    runtime_factor = RUNTIME_FACTORS.get(runtime_context, 1.0)
    if runtime_context == "unknown":
        missing.append("runtime_context")
        notes.append("Runtime context unknown: disclosed neutral exposure placeholder 50/100 used")

    if runtime_context == "unknown":
        provisional = True
    severity_score = round(cvss * 10, 1)
    exploit_score = round(signal * 100, 1)
    exposure_score = round(runtime_factor * 100, 1)
    propagation_score = min(100.0, max(0, affected_projects) * PROPAGATION_POINTS_PER_PROJECT)
    score = risk_formula(cvss, signal, runtime_factor, affected_projects)
    return RiskScore(
        score=score,
        priority=priority_for(score),
        factors=RiskFactors(
            cvss=cvss, cvss_source=vuln.cvss_source,
            exploit_signal=signal, exploit_source=source,
            runtime_factor=runtime_factor, runtime_context=runtime_context,
            severity_score=severity_score, exploit_score=exploit_score,
            exposure_score=exposure_score, propagation_score=propagation_score,
            affected_projects=max(0, affected_projects),
            formula=FORMULA,
        ),
        provisional=provisional,
        urgent_review=bool(vuln.in_kev),
        missing_data=missing,
        notes=notes,
    )
