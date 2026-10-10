"""Ordered remediation plan built from findings.

Recommendations are limited to what the advisory data supports: the fixed
version comes from the record's affected range and is re-checked against
every matched record. API compatibility is NOT verified - major-version
jumps are flagged and every step carries a regression-testing checklist.
Nothing is applied automatically.
"""

from __future__ import annotations

from collections import defaultdict

import networkx as nx

from schemas.scan_result import AffectedProject, Finding, PatchStep
from services import versioning
from services.risk_engine import priority_for

_PIN_HINT = {
    "npm": "an npm 'overrides' (or yarn 'resolutions') entry",
    "PyPI": "a pip constraints file / Poetry dependency entry",
    "Maven": "a <dependencyManagement> entry",
}
# Refresh only the affected package, to the advisory's fixed version - never "upgrade everything to latest".
_REFRESH_HINT = {
    "npm": "npm update {name}",
    "PyPI": 'pip install "{name}=={target}" (then re-pin)',
    "Maven": "mvn versions:use-dep-version -Dincludes={name} -DdepVersion={target}",
}


def step_key(ecosystem: str, name: str, version: str) -> str:
    return f"{ecosystem}:{name}@{version}"


def _max_version(ecosystem: str, versions: list[str]) -> str | None:
    best = None
    for v in versions:
        try:
            if best is None or versioning.compare(ecosystem, v, best) > 0:
                best = v
        except versioning.VersionParseError:
            return None
    return best


def upgrade_commands(ecosystem: str, name: str, target: str, has_direct: bool, has_transitive: bool,
                     dev_only: bool, poetry: bool) -> list[str]:
    cmds: list[str] = []
    if ecosystem == "npm":
        if has_direct:
            cmds.append(f"npm install {name}@{target}" + (" --save-dev" if dev_only else ""))
        if has_transitive:
            cmds += [f'npm pkg set "overrides.{name}={target}"', "npm install"]
        cmds.append(f"npm ls {name}")
    elif ecosystem == "PyPI":
        if poetry:
            cmds.append(f'poetry add "{name}>={target}"' if has_direct else f"poetry update {name}")
        cmds.append(f'pip install "{name}>={target}"')
        cmds.append(f"pip show {name}")
    else:
        group, _, artifact = name.partition(":")
        if has_direct:
            cmds.append(
                f"mvn versions:use-dep-version -Dincludes={group}:{artifact} -DdepVersion={target} -DforceVersion=true"
            )
        cmds.append(f"mvn dependency:tree -Dincludes={group}:{artifact}")
    return cmds


def _checklist(name: str, current: str, target: str | None, major: bool, transitive: bool,
               projects: list[str], range_min: bool) -> list[str]:
    items: list[str] = []
    if range_min:
        items.append(f"Confirm the installed version from the lockfile - {current} is only the lower bound of a declared range.")
    if target is None:
        items += [
            "Read the advisory for workarounds or vendor mitigations.",
            f"Evaluate replacing or removing {name}; restrict exposure of affected features meanwhile.",
            "Subscribe to the advisory and re-scan when a fixed release is published.",
        ]
    else:
        items.append(f"Review release notes / changelog between {current} and {target}.")
        if major:
            items.append("Major version change: follow the migration guide and audit breaking API changes.")
        if transitive:
            items.append(
                f"Check that every parent package's version range accepts {name} {target} (an override can break peer ranges)."
            )
        items.append("Regenerate the lockfile and confirm the resolved version with the verification command.")
    items += [
        f"Run unit, integration and end-to-end tests for: {', '.join(projects[:6])}{'...' if len(projects) > 6 else ''}.",
        "Deploy to a staging environment and monitor errors before production.",
        "Re-scan with HYRON AI - only a re-scan can mark this step as verified.",
    ]
    return items


def build_patch_plan(
    findings: list[Finding],
    g: nx.DiGraph,
    affected_entries: dict[tuple[str, str], dict],
) -> list[PatchStep]:
    by_node: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_node[f.package_node].append(f)

    steps: list[tuple[tuple, PatchStep]] = []
    for node, group in by_node.items():
        first = group[0]
        eco, name, current = first.ecosystem, first.package, first.version
        vuln_ids = [f.vulnerability.id for f in group]
        max_score = max(f.max_risk.score for f in group)
        warnings: list[str] = []

        # Each project's worst exposure across this package's advisories.
        project_impact: dict[str, AffectedProject] = {}
        for f in group:
            for ap in f.affected_projects:
                prev = project_impact.get(ap.project)
                if prev is None or ap.risk.score > prev.risk.score:
                    project_impact[ap.project] = ap
        ordered_projects = sorted(project_impact, key=lambda p: (-project_impact[p].risk.score, p))

        fixes = [f.vulnerability.fixed_version for f in group if f.vulnerability.fixed_version]
        unfixed = [f.vulnerability.id for f in group if not f.vulnerability.fixed_version]
        candidate = _max_version(eco, fixes) if fixes else None
        major = False

        if candidate is None:
            status = "no_fix_known"
            warnings.append(
                "No fixed version is published in the advisory data. Consider removing or replacing the package, "
                "or applying vendor mitigations; monitor the advisory."
            )
        else:
            status = "fix_available"
            if unfixed:
                status = "needs_review"
                warnings.append(f"{candidate} does not address {', '.join(unfixed)} (no fix published).")
            still = [
                f.vulnerability.id for f in group
                if versioning.is_affected(eco, candidate, affected_entries.get((node, f.vulnerability.id), {}))
            ]
            if still:
                status = "needs_review"
                warnings.append(f"{candidate} still falls inside the affected range of {', '.join(still)}.")
            cur_major, new_major = versioning.major_of(eco, current), versioning.major_of(eco, candidate)
            if cur_major is not None and new_major is not None and new_major > cur_major:
                major = True
                warnings.append(
                    f"Major version change ({current} -> {candidate}); breaking changes are likely - test before release."
                )
        if first.version_status == "range_min":
            warnings.append(
                f"Version {current} is the lower bound of a declared range; the installed version may already "
                "be newer. Confirm with a lockfile before patching."
            )
        if any(ap.inferred_link for ap in project_impact.values()):
            warnings.append("Some dependency paths include inferred links (no manifest stated them directly).")

        actions: list[str] = []
        for pid in ordered_projects:
            ap = project_impact[pid]
            if candidate is None:
                actions.append(f"{pid}: no verified fix - mitigate or replace {name} ({ap.relation} dependency).")
                continue
            if ap.relation == "direct":
                edge = g.edges.get((f"project:{pid}", node), {})
                declared = edge.get("declared")
                allowed = versioning.constraint_allows(eco, declared, candidate)
                if allowed is True and declared != current:
                    actions.append(
                        f"{pid}: declared constraint '{declared}' already admits {candidate} - refresh the lockfile "
                        f"({_REFRESH_HINT[eco].format(name=name, target=candidate)}) and verify the resolved version."
                    )
                else:
                    actions.append(f"{pid}: change {name} from '{declared or current}' to {candidate} in the manifest.")
            else:
                via = ap.path[1] if len(ap.path) > 2 else "a dependency"
                actions.append(
                    f"{pid}: {name} arrives transitively via {via}. Upgrade {via.rsplit('@', 1)[0]} to a release that "
                    f"requires {name} >= {candidate} (not verified here), or force it with {_PIN_HINT[eco]}."
                )

        has_direct = any(project_impact[p].relation == "direct" for p in ordered_projects)
        has_transitive = any(project_impact[p].relation == "transitive" for p in ordered_projects)
        dev_only = all(project_impact[p].runtime_context == "development" for p in ordered_projects)
        poetry = any(
            str(g.nodes[f"project:{p}"].get("source_file", "")).endswith(("poetry.lock", "pyproject.toml"))
            for p in ordered_projects if f"project:{p}" in g
        )
        commands = upgrade_commands(eco, name, candidate, has_direct, has_transitive, dev_only, poetry) if candidate else []

        prod_count = sum(1 for p in ordered_projects if project_impact[p].runtime_context != "development")
        shown = ", ".join(vuln_ids[:3]) + (f" and {len(vuln_ids) - 3} more" if len(vuln_ids) > 3 else "")
        fixed_text = f"upgrade to {candidate}" if candidate else "no fixed release is known"
        rationale = (
            f"{name}@{current} has {len(group)} matched advisor{'y' if len(group) == 1 else 'ies'} "
            f"({shown}); highest V-RPS {max_score} ({priority_for(max_score)}). "
            f"It potentially affects {len(ordered_projects)} project(s), {prod_count} via production or "
            f"unknown-scope paths; {fixed_text}."
        )
        step = PatchStep(
            step_key=step_key(eco, name, current), order=0, package=name, ecosystem=eco,
            current_version=current, recommended_version=candidate, fix_status=status,
            vulnerabilities=vuln_ids,
            advisory_urls=[f.vulnerability.source_url for f in group if f.vulnerability.source_url][:10],
            max_risk_score=max_score, priority=priority_for(max_score),
            urgent_review=any(f.max_risk.urgent_review for f in group),
            affected_projects=ordered_projects, actions=actions, upgrade_commands=commands,
            checklist=_checklist(name, current, candidate, major, has_transitive, ordered_projects,
                                 first.version_status == "range_min"),
            rationale=rationale, warnings=warnings,
        )
        steps.append(((-max_score, -prod_count, -len(ordered_projects), name), step))

    steps.sort(key=lambda s: s[0])
    for i, (_, step) in enumerate(steps, 1):
        step.order = i
    return [s for _, s in steps]
