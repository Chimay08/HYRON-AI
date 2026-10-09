"""HYRON Risk Score - a transparent, project-specific heuristic (NOT an industry standard).

    HYRON Risk Score = 100 x (CVSS / 10) x (0.2 + 0.8 x Exploit Signal) x Runtime Factor

The three inputs are reported separately so severity, exploitability and
exposure are never blended invisibly:

Severity (CVSS)
    From the advisory's CVSS v3 vector. If only a qualitative label exists
    (e.g. GHSA "HIGH"), the band mid-point is used and flagged. If nothing
    exists, UNKNOWN_CVSS is used, the score is marked provisional and the
    gap is listed in `missing_data`.
Exploitability (Exploit Signal)
    1.0 when the CVE is in CISA KEV, else its FIRST EPSS probability.
    No evidence -> UNKNOWN_EXPLOIT_SIGNAL (0.0); the 0.2 floor keeps severity
    contributing. Missing evidence is never treated as proof of safety.
Exposure (Runtime Factor)
    1.0 for production paths, 0.4 for development-only paths. Unknown context
    is scored like production (1.0) and flagged.

All weights live here and nowhere else.
"""

from __future__ import annotations

from schemas.scan_result import RiskFactors, RiskScore
from schemas.vulnerability import VulnerabilityInfo

SCORE_NAME = "HYRON Risk Score"
FORMULA = "100 x (CVSS/10) x (0.2 + 0.8 x ExploitSignal) x RuntimeFactor"

EXPLOIT_FLOOR = 0.2
KEV_SIGNAL = 1.0
UNKNOWN_EXPLOIT_SIGNAL = 0.0
UNKNOWN_CVSS = 5.0
RUNTIME_FACTORS = {"production": 1.0, "development": 0.4, "unknown": 1.0}

HIGH_THRESHOLD = 50.0
MEDIUM_THRESHOLD = 25.0


def describe() -> dict:
    """Machine-readable description of the heuristic, served by the API."""
    return {
        "name": SCORE_NAME,
        "formula": FORMULA,
        "standard": False,
        "weights": {
            "exploit_floor": EXPLOIT_FLOOR, "kev_signal": KEV_SIGNAL,
            "runtime_factors": RUNTIME_FACTORS,
        },
        "fallbacks": {
            "cvss_unknown": UNKNOWN_CVSS, "exploit_unknown": UNKNOWN_EXPLOIT_SIGNAL,
            "runtime_unknown": RUNTIME_FACTORS["unknown"],
        },
        "priority_thresholds": {"high": HIGH_THRESHOLD, "medium": MEDIUM_THRESHOLD},
        "urgent_review": "Any finding listed in CISA KEV is flagged for urgent review, independent of its score",
    }


def risk_formula(cvss: float, exploit_signal: float, runtime_factor: float) -> float:
    return round(100 * (cvss / 10) * (EXPLOIT_FLOOR + (1 - EXPLOIT_FLOOR) * exploit_signal) * runtime_factor, 1)


def priority_for(score: float) -> str:
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def score_vulnerability(vuln: VulnerabilityInfo, runtime_context: str) -> RiskScore:
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
        missing.append("exploit_evidence")
        if vuln.in_kev is None:
            notes.append("Exploit evidence unavailable (KEV/EPSS not retrieved) - not evidence of safety")
        else:
            notes.append("Not in CISA KEV and no EPSS score - exploit likelihood unknown")

    runtime_factor = RUNTIME_FACTORS.get(runtime_context, 1.0)
    if runtime_context == "unknown":
        missing.append("runtime_context")
        notes.append("Runtime context unknown: scored like production (factor 1.0)")

    score = risk_formula(cvss, signal, runtime_factor)
    return RiskScore(
        score=score,
        priority=priority_for(score),
        factors=RiskFactors(
            cvss=cvss, cvss_source=vuln.cvss_source,
            exploit_signal=signal, exploit_source=source,
            runtime_factor=runtime_factor, runtime_context=runtime_context,
            formula=FORMULA,
        ),
        provisional=provisional,
        urgent_review=bool(vuln.in_kev),
        missing_data=missing,
        notes=notes,
    )
