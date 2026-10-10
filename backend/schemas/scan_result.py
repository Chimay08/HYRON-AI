"""Pydantic models shared by the parser, scanner, graph, risk engine and API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from schemas.vulnerability import DataSource, VulnerabilityInfo

__all__ = ["DataSource", "VulnerabilityInfo"]  # re-exported for convenience

Ecosystem = Literal["npm", "PyPI", "Maven"]
# production  -> ships with / runs in the deployed application
# development -> dev/test/build-only dependency
# unknown     -> the input does not say
Scope = Literal["production", "development", "unknown"]
# exact      -> resolved/pinned version, scanned as-is
# range_min  -> only a constraint was declared; its lower bound is scanned
# unresolved -> no concrete version could be derived; not scanned
VersionStatus = Literal["exact", "range_min", "unresolved"]
RemediationStatus = Literal["open", "under_review", "resolved_reported", "verified_by_rescan", "still_detected"]


# ---------------------------------------------------------------- parsing ---

class Dependency(BaseModel):
    name: str
    ecosystem: Ecosystem
    version: str | None = None
    declared: str | None = None
    version_status: VersionStatus = "exact"
    scope: Scope = "unknown"
    # True when the link from the parent was inferred rather than stated
    # (e.g. poetry.lock without pyproject.toml: roots attached to the project).
    inferred: bool = False
    dependencies: list["Dependency"] = Field(default_factory=list)


class Project(BaseModel):
    name: str
    ecosystem: Ecosystem
    source_file: str
    # True only when the input describes the resolved transitive tree
    # (lockfiles, Maven dependency:tree, dependency-tree JSON).
    has_transitive_data: bool = False
    dependencies: list[Dependency] = Field(default_factory=list)


class ParseIssue(BaseModel):
    file: str
    message: str
    level: Literal["info", "warning", "error"] = "warning"


# ------------------------------------------------------------------ risk ---

class RiskFactors(BaseModel):
    cvss: float
    cvss_source: str
    exploit_signal: float
    exploit_source: Literal["cisa_kev", "epss", "unknown"]
    runtime_factor: float
    runtime_context: Scope
    severity_score: float
    exploit_score: float
    exposure_score: float
    propagation_score: float
    affected_projects: int
    formula: str


class RiskScore(BaseModel):
    """HYRON Risk Score - a project-specific heuristic, not an industry standard."""
    score: float
    priority: Literal["critical", "high", "medium", "low"]
    factors: RiskFactors
    # True when any factor used a documented fallback instead of evidence.
    provisional: bool = False
    # Known-exploited (CISA KEV) issues are flagged for urgent review whatever their score,
    # e.g. a KEV vulnerability on a development-only path still needs a prompt decision.
    urgent_review: bool = False
    missing_data: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class AffectedProject(BaseModel):
    project: str
    relation: Literal["direct", "transitive"]
    path: list[str]                      # human-readable labels, project first
    runtime_context: Scope
    inferred_link: bool = False
    risk: RiskScore


class Exposure(BaseModel):
    """Business exposure, kept separate from severity and exploitability."""
    affected_projects: int
    production_projects: int
    development_only_projects: int
    unknown_context_projects: int
    direct_dependents: int
    transitive_dependents: int


class Finding(BaseModel):
    finding_id: str
    package_node: str
    package: str
    ecosystem: Ecosystem
    version: str
    version_status: VersionStatus
    vulnerability: VulnerabilityInfo
    max_risk: RiskScore
    exposure: Exposure
    affected_projects: list[AffectedProject]
    explanation: str = ""


# ----------------------------------------------------------------- patch ---

class PatchStep(BaseModel):
    step_key: str
    order: int
    package: str
    ecosystem: Ecosystem
    current_version: str
    recommended_version: str | None
    fix_status: Literal["fix_available", "no_fix_known", "needs_review"]
    vulnerabilities: list[str]
    advisory_urls: list[str] = Field(default_factory=list)
    max_risk_score: float
    priority: Literal["critical", "high", "medium", "low"]
    urgent_review: bool = False
    affected_projects: list[str]
    actions: list[str]
    upgrade_commands: list[str] = Field(default_factory=list)
    checklist: list[str] = Field(default_factory=list)
    rationale: str
    warnings: list[str] = Field(default_factory=list)
    remediation_status: RemediationStatus = "open"
    status_note: str = ""
    status_updated_at: str | None = None


class ResolvedItem(BaseModel):
    step_key: str
    package: str
    version: str
    vulnerabilities: list[str]
    previous_scan_id: str


# ----------------------------------------------------------------- graph ---

class GraphNode(BaseModel):
    id: str
    label: str
    type: Literal["project", "package"]
    status: Literal["vulnerable", "affected", "clean", "unscanned"]
    ecosystem: str | None = None
    version: str | None = None
    version_status: str | None = None
    depth: int | None = None             # shortest distance from any project
    vulnerabilities: list[str] = Field(default_factory=list)
    max_risk_score: float | None = None
    priority: str | None = None
    severity: str | None = None


class GraphEdge(BaseModel):
    source: str
    target: str
    scope: Scope
    inferred: bool = False


class GraphData(BaseModel):
    scan_id: str
    complete: bool
    completeness_note: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]


# --------------------------------------------------------------- reports ---

class CoverageGap(BaseModel):
    package: str
    ecosystem: str
    declared: str | None
    reason: str


class ScanSource(BaseModel):
    type: Literal["upload", "repository", "demo"]
    label: str
    url: str | None = None
    branch: str | None = None
    commit: str | None = None
    files: list[str] = Field(default_factory=list)
    private: bool = False


class ScanSummary(BaseModel):
    total_projects: int
    total_packages: int
    scanned_packages: int
    unscanned_packages: int
    vulnerable_packages: int
    affected_projects: int
    high_priority_findings: int
    total_findings: int
    direct_packages: int = 0
    transitive_packages: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    priority_counts: dict[str, int] = Field(default_factory=dict)
    total_risk: float = 0.0


class ScanReport(BaseModel):
    kind: Literal["dependency"] = "dependency"
    scan_id: str
    created_at: str
    mode: Literal["demo", "live"]
    status: Literal["completed", "completed_with_gaps", "verification_failed"]
    status_detail: str
    data_notice: str
    source: ScanSource
    summary: ScanSummary
    projects: list[str]
    findings: list[Finding]
    patch_plan: list[PatchStep]
    coverage_gaps: list[CoverageGap]
    warnings: list[str]
    limitations: list[str]
    data_sources: list[DataSource]
    parse_issues: list[ParseIssue]
    resolved_since_previous: list[ResolvedItem] = Field(default_factory=list)
    previous_scan_id: str | None = None


class ScanListItem(BaseModel):
    scan_id: str
    kind: Literal["dependency", "website"]
    created_at: str
    mode: str
    status: str
    source_type: str
    label: str
    url: str | None = None
    branch: str | None = None
    summary: ScanSummary | None = None
    website_counts: dict[str, int] | None = None


# --------------------------------------------------------------- website ---

class DetectedTechnology(BaseModel):
    name: str
    version: str | None = None
    category: str
    evidence: str
    confidence: Literal["high", "medium", "low"]
    npm_package: str | None = None


class PotentialExposure(BaseModel):
    technology: str
    npm_package: str
    version: str
    evidence: str
    vulnerability: VulnerabilityInfo


class WebsiteReport(BaseModel):
    kind: Literal["website"] = "website"
    scan_id: str
    created_at: str
    url: str
    final_url: str
    http_status: int
    status: Literal["completed", "completed_with_gaps", "verification_failed"]
    status_detail: str
    technologies: list[DetectedTechnology]
    potential_exposures: list[PotentialExposure]
    confirmed_vulnerabilities: list[str] = Field(default_factory=list)  # always empty: see notice
    notice: str
    limitations: list[str]
    data_sources: list[DataSource]


# ------------------------------------------------------------------- API ---

class PRDraftRequest(BaseModel):
    step_key: str = Field(..., max_length=300)


class PRDraft(BaseModel):
    title: str
    branch: str
    body: str
    suggested_changes: list[str]
    compare_url: str | None = None
    note: str


class ExplainRequest(BaseModel):
    finding_id: str | None = None


class ExplainResponse(BaseModel):
    scan_id: str
    finding_id: str | None = None
    source: Literal["ai", "deterministic"]
    model: str | None = None
    explanation: str
    note: str = ""


class RepositoryRequest(BaseModel):
    url: str = Field(..., max_length=300)
    branch: str | None = Field(None, max_length=200)


class RepositoryInfo(BaseModel):
    owner: str
    repo: str
    full_name: str
    html_url: str
    private: bool
    default_branch: str
    branch: str
    commit: str
    branches: list[str]
    manifests: list[str]
    skipped: list[str] = Field(default_factory=list)
    truncated: bool = False
    auth: Literal["token", "anonymous"]


class WebsiteRequest(BaseModel):
    url: str = Field(..., max_length=500)
    acknowledge_passive: bool = Field(
        False, description="Must be true: confirms this is a passive, read-only inspection of a public page."
    )


class StatusUpdate(BaseModel):
    step_key: str = Field(..., max_length=300)
    status: Literal["open", "under_review", "resolved_reported"]
    confirm: bool = Field(False, description="Required (true) when reporting a fix as resolved.")
    note: str = Field("", max_length=500)
