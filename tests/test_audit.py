"""QA audit: regression tests for bugs fixed during the audit, plus the propagation,
scoring and end-to-end scenarios from the audit brief. All HTTP is mocked."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from schemas.scan_result import Dependency, Project, VulnerabilityInfo
from services import dependency_graph as dg
from services import osv_service
from services.manifest_parser import parse_files
from services.osv_service import EPSS_URL, KEV_URL, OSV_API
from services.pipeline import _dedupe_project_names
from services.risk_engine import priority_for, risk_formula, score_vulnerability

WS = {"X-Workspace-Id": "c" * 32}


@pytest.fixture
def client():
    from main import app
    return TestClient(app)


def osv_record(vid, name, ecosystem, fixed, cve=None, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
    return {
        "id": vid, "aliases": [cve] if cve else [], "summary": f"Test advisory {vid}",
        "severity": [{"type": "CVSS_V3", "score": vector}],
        "affected": [{"package": {"name": name, "ecosystem": ecosystem},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}],
    }


@pytest.fixture
def fake_osv(monkeypatch):
    """Serve OSV / KEV / EPSS from in-memory data and record every request body."""
    state = {"records": {}, "batch_ids": {}, "kev": [], "epss": {}, "pages": {}, "bodies": []}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == f"{OSV_API}/querybatch":
            body = json.loads(request.content)
            state["bodies"].append(body)
            results = []
            for q in body["queries"]:
                key = (q["package"]["name"], q["version"])
                res = {"vulns": [{"id": i} for i in state["batch_ids"].get(key, [])]}
                if key in state["pages"]:
                    res["next_page_token"] = "page-2"
                results.append(res)
            return httpx.Response(200, json={"results": results})
        if url == f"{OSV_API}/query":
            body = json.loads(request.content)
            state["bodies"].append(body)
            key = (body["package"]["name"], body["version"])
            return httpx.Response(200, json={"vulns": [{"id": i} for i in state["pages"].get(key, [])]})
        if url.startswith(f"{OSV_API}/vulns/"):
            vid = url.rsplit("/", 1)[-1]
            rec = state["records"].get(vid)
            return httpx.Response(200, json=rec) if rec else httpx.Response(404)
        if url == KEV_URL:
            return httpx.Response(200, json={"vulnerabilities": [{"cveID": c} for c in state["kev"]]})
        if url.startswith(EPSS_URL):
            return httpx.Response(200, json={"data": [{"cve": c, "epss": str(v)} for c, v in state["epss"].items()]})
        return httpx.Response(404)

    monkeypatch.setattr(osv_service, "new_client",
                        lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    return state


# ------------------------------------------------------------ parsing fixes

def test_empty_version_operator_is_unresolved():
    # Regression: "requests===" used to become version "" with status "exact".
    projects, _ = parse_files([("requirements.txt", b"requests===\nflask==2.0.1\n")])
    deps = {d.name: d for d in projects[0].dependencies}
    assert deps["requests"].version is None and deps["requests"].version_status == "unresolved"
    assert deps["flask"].version == "2.0.1" and deps["flask"].version_status == "exact"


def test_empty_version_is_never_sent_to_osv(client, fake_osv):
    # Regression: an empty version made OSV return every advisory for the package (16 false findings).
    fake_osv["batch_ids"][("requests", "")] = ["GHSA-should-not-match"]
    r = client.post("/api/scan", headers=WS, files=[("files", ("requirements.txt", b"requests===\n"))])
    assert r.status_code == 201
    report = r.json()
    assert report["findings"] == []
    assert report["status"] == "completed_with_gaps"
    assert [g["package"] for g in report["coverage_gaps"]] == ["requests"]
    assert not any(q["version"] == "" for b in fake_osv["bodies"] for q in b.get("queries", [b]))
    node = next(n for n in client.get(f"/api/graph/{report['scan_id']}", headers=WS).json()["nodes"]
                if n["type"] == "package")
    assert node["status"] == "unscanned"


def test_requirements_duplicate_with_conflicting_versions_is_reported():
    projects, issues = parse_files([("requirements.txt", b"requests==2.19.0\nrequests==2.25.0\nRequests==2.19.0\n")])
    versions = sorted(d.version for d in projects[0].dependencies)
    assert versions == ["2.19.0", "2.25.0"]          # exact repeat merged, conflict kept
    assert any("listed more than once" in i.message for i in issues)


@pytest.mark.parametrize("filename,content", [
    ("requirements.txt", b""),
    ("requirements.txt", b"# only a comment\n"),
    ("package.json", b"{}"),
    ("package.json", b'{"name": "x", "dependencies": {}}'),
])
def test_scan_without_dependencies_is_rejected_not_reported_clean(client, filename, content):
    # Regression: these returned 201 "completed - all resolvable package versions were checked".
    r = client.post("/api/scan", headers=WS, files=[("files", (filename, content))])
    assert r.status_code == 422
    assert "No dependencies were found" in r.json()["detail"]["message"]


def test_project_name_dedupe_never_collides():
    projects = [Project(name=n, ecosystem="npm", source_file="t") for n in ("app", "app-2", "app")]
    _dedupe_project_names(projects)
    names = [p.name for p in projects]
    assert len(set(names)) == 3 and names[:2] == ["app", "app-2"]


# ------------------------------------------------------------- API safety

def test_oversized_request_rejected_before_parsing(client, monkeypatch):
    import main
    monkeypatch.setattr(main, "MAX_REQUEST_BYTES", 1_000)
    r = client.post("/api/scan", headers=WS, files=[("files", ("requirements.txt", b"a==1.0\n" * 500))])
    assert r.status_code == 413


def test_ai_explanations_are_rate_limited_only_when_ai_is_used(client, monkeypatch):
    from routes import reports
    from schemas.scan_result import ExplainResponse
    from services.security import AI_LIMITER

    sid = client.post("/api/demo", headers=WS).json()["scan_id"]
    for _ in range(5):  # deterministic explanations: no limit
        assert client.post(f"/api/reports/{sid}/explain", headers=WS, json={}).status_code == 200

    async def fake_explain(report, finding=None):
        return ExplainResponse(scan_id=report.scan_id, source="ai", explanation="stub")

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    monkeypatch.setattr(reports.ai_explainer, "explain", fake_explain)
    monkeypatch.setattr(AI_LIMITER, "limit", 2)
    codes = [client.post(f"/api/reports/{sid}/explain", headers=WS, json={}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


# ------------------------------------------------------------ OSV handling

def test_osv_pagination_is_followed(client, fake_osv):
    # Regression: only the first page of OSV results was used (a warning was the only signal).
    fake_osv["batch_ids"][("lodash", "4.17.15")] = ["GHSA-page-0001"]
    fake_osv["pages"][("lodash", "4.17.15")] = ["GHSA-page-0002"]
    for vid in ("GHSA-page-0001", "GHSA-page-0002"):
        fake_osv["records"][vid] = osv_record(vid, "lodash", "npm", "4.17.21")
    r = client.post("/api/scan", headers=WS,
                    files=[("files", ("package.json", b'{"dependencies": {"lodash": "4.17.15"}}'))])
    ids = sorted(f["vulnerability"]["id"] for f in r.json()["findings"])
    assert ids == ["GHSA-page-0001", "GHSA-page-0002"]
    assert any("page_token" in b for b in fake_osv["bodies"])


# ---------------------------------------------- dependency propagation (§6)

def dep(name, scope="production", children=()):
    return Dependency(name=name, ecosystem="npm", version="1.0.0", declared="1.0.0",
                      version_status="exact", scope=scope, dependencies=list(children))


def proj(name, *deps):
    return Project(name=name, ecosystem="npm", source_file="t", has_transitive_data=True, dependencies=list(deps))


C = "npm:c@1.0.0"


def test_chain_project_a_to_b_to_c():
    g = dg.build_graph([proj("A", dep("b", children=[dep("c")]))])
    # Edges point dependent -> dependency, so consumers are ancestors of the vulnerable node.
    assert g.has_edge("project:A", "npm:b@1.0.0") and g.has_edge("npm:b@1.0.0", C)
    assert not g.has_edge(C, "npm:b@1.0.0")
    [impact] = dg.blast_radius(g, C)
    assert impact.project == "project:A" and impact.relation == "transitive"
    assert impact.path == ["project:A", "npm:b@1.0.0", C]
    assert dg.direct_parent(impact.path) == "npm:b@1.0.0"


def test_project_with_many_paths_is_counted_once_and_direct_wins():
    g = dg.build_graph([proj("E", dep("b", children=[dep("c")]), dep("d", children=[dep("c")]), dep("c"))])
    impacts = dg.blast_radius(g, C)
    assert [(i.project, i.relation) for i in impacts] == [("project:E", "direct")]


def test_shared_dependency_reaches_multiple_projects():
    shared = dep("b", children=[dep("c")])
    g = dg.build_graph([proj("A", shared), proj("B2", shared), proj("Z", dep("z"))])
    assert sorted(i.project for i in dg.blast_radius(g, C)) == ["project:A", "project:B2"]


def test_cycles_and_duplicate_edges_terminate():
    cyc = dep("x", children=[dep("y", children=[dep("x"), dep("c")])])
    g = dg.build_graph([proj("F", cyc, cyc)])
    [impact] = dg.blast_radius(g, C)
    assert impact.project == "project:F" and impact.path[-1] == C
    assert g.number_of_edges() == 4  # F->x, x->y, y->x, y->c: duplicates merged


def test_vulnerable_package_used_by_nobody_affects_no_project():
    g = dg.build_graph([proj("A", dep("b"))])
    g.add_node("npm:orphan@1.0.0", type="package", name="orphan", ecosystem="npm", version="1.0.0",
               declared=None, version_status="exact")
    assert dg.blast_radius(g, "npm:orphan@1.0.0") == []


# --------------------------------------------------------- risk score (§7)

def vuln(cvss=9.8, kev=False, epss=None, source="vector"):
    return VulnerabilityInfo(id="T-1", cvss_score=cvss, cvss_source=source, in_kev=kev, epss=epss)


@pytest.mark.parametrize("v,ctx,expected,priority", [
    (vuln(9.8, kev=True), "production", 87.3, "critical"),
    (vuln(9.8, kev=True), "development", 75.3, "high"),
    (vuln(5.3, epss=0.35), "production", 52.0, "medium"),
    (vuln(7.5, kev=False), "production", 64.2, "high"),
])
def test_documented_score_examples(v, ctx, expected, priority):
    s = score_vulnerability(v, ctx)
    assert s.score == expected and s.priority == priority


def test_known_exploited_is_flagged_urgent_even_when_score_is_not_high():
    s = score_vulnerability(vuln(9.8, kev=True), "development")
    assert s.priority == "high" and s.urgent_review is True
    assert any("CISA KEV" in n for n in s.notes)
    assert score_vulnerability(vuln(9.8, epss=0.9), "production").urgent_review is False


def test_score_bounds_and_band_edges():
    assert risk_formula(10.0, 1.0, 1.0, 5) == 100.0
    assert risk_formula(0.0, 0.0, 0.0, 0) == 0.0
    assert [priority_for(x) for x in (80.0, 79.9, 60.0, 59.9, 35.0, 34.9)] == ["critical", "high", "high", "medium", "medium", "low"]


def test_missing_inputs_are_disclosed_not_treated_as_safe():
    s = score_vulnerability(VulnerabilityInfo(id="T-2", cvss_score=None, cvss_source="unknown", in_kev=None), "unknown")
    assert s.provisional is True
    assert set(s.missing_data) == {"cvss", "exploit_evidence", "runtime_context"}
    assert s.score == 45.5  # disclosed neutral fallbacks plus one affected project


# ----------------------------------------------------- patch planning (§8)

def test_refresh_hint_targets_fixed_version_not_latest(client, fake_osv):
    fake_osv["batch_ids"][("flask", "2.0")] = ["PYSEC-test-1"]
    fake_osv["records"]["PYSEC-test-1"] = osv_record("PYSEC-test-1", "flask", "PyPI", "2.2.5")
    r = client.post("/api/scan", headers=WS, files=[("files", ("requirements.txt", b"flask>=2.0\n"))])
    [step] = r.json()["patch_plan"]
    assert step["recommended_version"] == "2.2.5" and step["fix_status"] == "fix_available"
    action = step["actions"][0]
    assert "already admits 2.2.5" in action and 'flask==2.2.5' in action and "--upgrade" not in action


# ------------------------------------------- end-to-end, offline (§12)

def test_end_to_end_upload_to_remediation_offline(client, fake_osv):
    """Lockfile upload -> parse -> match (mocked OSV, labelled test data) -> graph ->
    affected projects -> score -> patch plan -> report/graph payloads used by the dashboard."""
    lock = {
        "name": "web-shop", "lockfileVersion": 3,
        "packages": {
            "": {"name": "web-shop", "dependencies": {"http-lib": "1.0.0"}, "devDependencies": {"test-kit": "1.0.0"}},
            "node_modules/http-lib": {"version": "1.0.0", "dependencies": {"url-lib": "2.0.0"}},
            "node_modules/url-lib": {"version": "2.0.0"},
            "node_modules/test-kit": {"version": "1.0.0", "dev": True, "dependencies": {"yaml-lib": "0.1.0"}},
            "node_modules/yaml-lib": {"version": "0.1.0", "dev": True},
        },
    }
    fake_osv["batch_ids"][("url-lib", "2.0.0")] = ["GHSA-test-url"]
    fake_osv["batch_ids"][("yaml-lib", "0.1.0")] = ["GHSA-test-yaml"]
    fake_osv["records"]["GHSA-test-url"] = osv_record("GHSA-test-url", "url-lib", "npm", "2.0.3", cve="CVE-2099-1111")
    no_fix = osv_record("GHSA-test-yaml", "yaml-lib", "npm", "9.9.9")
    no_fix["affected"][0]["ranges"][0]["events"] = [{"introduced": "0"}]   # missing fixed version
    no_fix["severity"] = []                                               # missing CVSS
    fake_osv["records"]["GHSA-test-yaml"] = no_fix
    fake_osv["kev"] = ["CVE-2099-1111"]

    r = client.post("/api/scan", headers=WS, files=[
        ("files", ("package-lock.json", json.dumps(lock).encode())),
        ("files", ("package.json", json.dumps(lock["packages"][""]).encode())),
    ])
    assert r.status_code == 201
    report = r.json()
    assert report["mode"] == "live" and report["status"] == "completed"
    by_pkg = {f["package"]: f for f in report["findings"]}

    url = by_pkg["url-lib"]
    assert url["vulnerability"]["match_basis"] == "local_range_check"
    [ap] = url["affected_projects"]
    assert ap["relation"] == "transitive" and ap["path"] == ["web-shop", "http-lib@1.0.0", "url-lib@2.0.0"]
    assert url["max_risk"]["score"] == 87.3 and url["max_risk"]["urgent_review"] is True

    yaml = by_pkg["yaml-lib"]
    assert yaml["affected_projects"][0]["runtime_context"] == "development"
    assert yaml["max_risk"]["provisional"] is True and "cvss" in yaml["max_risk"]["missing_data"]

    plan = report["patch_plan"]
    assert [s["package"] for s in plan] == ["url-lib", "yaml-lib"]
    assert plan[0]["recommended_version"] == "2.0.3" and plan[0]["urgent_review"] is True
    assert plan[1]["recommended_version"] is None and plan[1]["fix_status"] == "no_fix_known"

    s = report["summary"]
    assert (s["vulnerable_packages"], s["affected_projects"], s["total_findings"]) == (2, 1, 2)

    graph = client.get(f"/api/graph/{report['scan_id']}", headers=WS).json()
    status = {n["label"]: n["status"] for n in graph["nodes"]}
    assert status["url-lib@2.0.0"] == "vulnerable" and status["http-lib@1.0.0"] == "affected"
    assert status["web-shop"] == "affected" and graph["complete"] is True
