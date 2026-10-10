import asyncio

import pytest
from fastapi.testclient import TestClient

from schemas.scan_result import Dependency, Project, VulnerabilityInfo
from services import dependency_graph as dg
from services.risk_engine import risk_formula, score_vulnerability


def dep(name, version, scope="production", children=()):
    return Dependency(name=name, ecosystem="npm", version=version, scope=scope, dependencies=list(children))


@pytest.fixture
def graph():
    projects = [
        Project(name="direct-app", ecosystem="npm", source_file="t", dependencies=[dep("vuln", "1.0.0")]),
        Project(name="trans-app", ecosystem="npm", source_file="t",
                dependencies=[dep("mid", "2.0.0", children=[dep("vuln", "1.0.0")])]),
        Project(name="dev-app", ecosystem="npm", source_file="t",
                dependencies=[dep("tool", "3.0.0", "development", children=[dep("vuln", "1.0.0", "development")])]),
        Project(name="unknown-app", ecosystem="npm", source_file="t",
                dependencies=[dep("vuln", "1.0.0", "unknown")]),
        Project(name="clean-app", ecosystem="npm", source_file="t", dependencies=[dep("other", "1.0.0")]),
    ]
    return dg.build_graph(projects)


VULN = "npm:vuln@1.0.0"


def test_graph_shares_package_nodes(graph):
    assert graph.in_degree(VULN) == 4  # one node, four dependents
    assert graph.nodes[VULN]["type"] == "package"
    assert graph.has_edge("project:trans-app", "npm:mid@2.0.0")


def test_blast_radius_direct_and_transitive(graph):
    impacts = {graph.nodes[i.project]["name"]: i for i in dg.blast_radius(graph, VULN)}
    assert set(impacts) == {"direct-app", "trans-app", "dev-app", "unknown-app"}
    assert impacts["direct-app"].relation == "direct"
    assert impacts["trans-app"].relation == "transitive"
    assert impacts["trans-app"].path == ["project:trans-app", "npm:mid@2.0.0", VULN]


def test_runtime_context(graph):
    impacts = {graph.nodes[i.project]["name"]: i.runtime_context for i in dg.blast_radius(graph, VULN)}
    assert impacts == {
        "direct-app": "production", "trans-app": "production",
        "dev-app": "development", "unknown-app": "unknown",
    }


def test_potentially_affected_includes_intermediate_packages(graph):
    affected = dg.potentially_affected_nodes(graph, {VULN})
    assert "npm:mid@2.0.0" in affected and "project:trans-app" in affected
    assert "project:clean-app" not in affected and VULN not in affected


# ------------------------------------------------------------------ risk

@pytest.mark.parametrize("cvss,signal,runtime,expected", [
    (9.8, 1.0, 1.0, 87.3),     # KEV, production, one affected project
    (9.8, 1.0, 0.4, 75.3),     # KEV, dev-only, one affected project
    (5.3, 0.35, 1.0, 52.0),    # EPSS 0.35, one affected project
    (7.5, 0.0, 1.0, 49.2),     # explicit zero exploit signal
    (10.0, 1.0, 1.0, 88.0),
])
def test_risk_formula(cvss, signal, runtime, expected):
    assert risk_formula(cvss, signal, runtime) == expected


def test_score_vulnerability_factors_and_fallbacks():
    kev = VulnerabilityInfo(id="X", cvss_score=9.8, cvss_source="vector", in_kev=True, epss=0.1)
    s = score_vulnerability(kev, "production")
    assert s.score == 87.3 and s.priority == "critical" and not s.provisional and s.missing_data == []
    assert s.factors.exploit_source == "cisa_kev" and s.factors.exploit_signal == 1.0

    unknown = VulnerabilityInfo(id="Y", in_kev=None)
    s = score_vulnerability(unknown, "unknown")
    assert s.factors.cvss == 5.0 and s.factors.exploit_source == "unknown" and s.factors.runtime_factor == 0.5
    assert s.score == 45.5 and s.priority == "medium"
    assert s.provisional and s.missing_data == ["cvss", "exploit_evidence", "runtime_context"]
    assert any("provisional" in n for n in s.notes)
    assert any("not evidence of safety" in n for n in s.notes)


# -------------------------------------------------- end-to-end demo + plan

@pytest.fixture
def client():
    from main import app
    return TestClient(app)


def test_demo_end_to_end(client):
    r = client.post("/api/demo")
    assert r.status_code == 201
    report = r.json()
    assert report["mode"] == "demo" and "SIMULATED" in report["data_notice"]
    assert report["status"] == "completed" and report["source"]["type"] == "demo"
    assert report["data_sources"][0]["status"] == "synthetic"
    s = report["summary"]
    assert (s["vulnerable_packages"], s["affected_projects"], s["high_priority_findings"]) == (3, 4, 2)

    url = next(f for f in report["findings"] if f["package"] == "@hyron-demo/url-parser")
    rel = {a["project"]: (a["relation"], a["runtime_context"], a["risk"]["score"]) for a in url["affected_projects"]}
    assert rel == {
        "payments-api": ("direct", "production", 96.3),
        "checkout-service": ("transitive", "production", 96.3),
        "reporting-worker": ("transitive", "production", 96.3),
        "admin-portal": ("transitive", "development", 84.3),
    }
    # The http-client advisory only covers 1.x, so 2.3.0 must not be reported.
    assert all(f["vulnerability"]["id"] != "HYRON-DEMO-2026-0004" for f in report["findings"])

    plan = report["patch_plan"]
    assert [p["package"] for p in plan] == [
        "@hyron-demo/url-parser", "@hyron-demo/yaml-lite", "@hyron-demo/logger",
    ]
    assert [p["order"] for p in plan] == [1, 2, 3]
    assert plan[0]["recommended_version"] == "1.4.5" and plan[0]["fix_status"] == "fix_available"
    assert plan[0]["affected_projects"][-1] == "admin-portal"  # dev-only exposure last
    no_fix = next(p for p in plan if p["fix_status"] == "no_fix_known")
    assert no_fix["recommended_version"] is None and no_fix["package"] == "@hyron-demo/yaml-lite"

    g = client.get(f"/api/graph/{report['scan_id']}").json()
    status = {n["label"]: n["status"] for n in g["nodes"]}
    assert status["@hyron-demo/url-parser@1.4.2"] == "vulnerable"
    assert status["@hyron-demo/http-client@2.3.0"] == "affected"
    assert status["docs-site"] == "clean"

    assert client.get(f"/api/reports/{report['scan_id']}").json()["scan_id"] == report["scan_id"]
    explain = client.post(f"/api/reports/{report['scan_id']}/explain").json()
    assert explain["source"] == "deterministic" and "SIMULATED" in explain["explanation"]
    assert g["complete"] is True


def test_patch_plan_flags_range_min_and_major_bump():
    from schemas.scan_result import ScanSource
    from services.pipeline import run_scan

    data = {
        "vulnerabilities": [{
            "id": "HYRON-DEMO-T1", "severity": [],
            "affected": [{"package": {"ecosystem": "npm", "name": "lib"},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}],
        }],
        "exploit_intel": {},
    }
    project = Project(name="app", ecosystem="npm", source_file="package.json", dependencies=[
        Dependency(name="lib", ecosystem="npm", version="1.2.0", declared="^1.2.0",
                   version_status="range_min", scope="production"),
    ])
    report, _ = asyncio.run(run_scan(
        [project], mode="demo", demo_data=data, source=ScanSource(type="upload", label="t", files=["package.json"])))
    step = report.patch_plan[0]
    assert step.recommended_version == "2.0.0"
    text = " ".join(step.warnings)
    assert "lower bound" in text and "Major version change" in text
    assert "change lib from '^1.2.0' to 2.0.0" in step.actions[0]  # ^1.2.0 does not admit 2.0.0
    assert any("direct dependencies only" in w for w in report.warnings)
    assert step.upgrade_commands[0] == "npm install lib@2.0.0"
    assert any("Major version change" in c for c in step.checklist)
    assert any("lower bound" in c for c in step.checklist)


# ------------------------------------------------------------- API errors

def test_api_errors(client):
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/api/graph/nope").status_code == 404
    assert client.get("/api/reports/nope").status_code == 404
    r = client.post("/api/scan", files={"files": ("setup.py", b"x")})
    assert r.status_code == 415
    r = client.post("/api/scan", files={"files": ("requirements.txt", b"a" * 1_000_001)})
    assert r.status_code == 413
    r = client.post("/api/scan", files={"files": ("package.json", b"{broken")})
    assert r.status_code == 422 and "invalid JSON" in str(r.json())
