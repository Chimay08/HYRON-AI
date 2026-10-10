"""API behaviour: workspaces, history, remediation status, re-scan verification, failure handling."""

import asyncio
import copy

import httpx
import pytest
from fastapi.testclient import TestClient

from schemas.scan_result import ScanSource
from services import github_service, osv_service
from services.manifest_parser import parse_dependency_tree
from services.pipeline import load_demo_data, run_scan

WS_A = {"X-Workspace-Id": "a" * 32}
WS_B = {"X-Workspace-Id": "b" * 32}


@pytest.fixture
def client():
    from main import app
    return TestClient(app)


def test_meta_exposes_no_secrets(client, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_supersecret")
    body = client.get("/api/meta").text
    assert "ghp_supersecret" not in body
    assert client.get("/api/meta").json()["integrations"]["github"]["token_configured"] is True


def test_workspace_isolation_and_history(client):
    scan = client.post("/api/demo", headers=WS_A).json()
    assert [s["scan_id"] for s in client.get("/api/scans", headers=WS_A).json()] == [scan["scan_id"]]
    assert client.get("/api/scans", headers=WS_B).json() == []
    assert client.get(f"/api/reports/{scan['scan_id']}", headers=WS_B).status_code == 404
    assert client.get(f"/api/graph/{scan['scan_id']}", headers=WS_B).status_code == 404
    assert client.get("/api/scans", headers={"X-Workspace-Id": "bad id!"}).status_code == 400


def test_export_json(client):
    scan = client.post("/api/demo", headers=WS_A).json()
    r = client.get(f"/api/reports/{scan['scan_id']}/export", headers=WS_A)
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert r.json()["scan_id"] == scan["scan_id"]


def test_remediation_status_flow(client):
    scan = client.post("/api/demo", headers=WS_A).json()
    key = scan["patch_plan"][0]["step_key"]
    url = f"/api/reports/{scan['scan_id']}/remediation/status"
    r = client.post(url, headers=WS_A, json={"step_key": key, "status": "under_review"})
    assert r.status_code == 200 and r.json()["remediation_status"] == "under_review"
    # resolving needs explicit confirmation
    assert client.post(url, headers=WS_A, json={"step_key": key, "status": "resolved_reported"}).status_code == 422
    r = client.post(url, headers=WS_A, json={"step_key": key, "status": "resolved_reported", "confirm": True})
    assert r.json()["remediation_status"] == "resolved_reported"
    assert "not verified" in r.json()["status_note"]
    # users cannot claim re-scan verification
    assert client.post(url, headers=WS_A, json={"step_key": key, "status": "verified_by_rescan"}).status_code == 422
    # a re-scan that still finds it says so
    again = client.post("/api/demo", headers=WS_A).json()
    step = next(s for s in again["patch_plan"] if s["step_key"] == key)
    assert step["remediation_status"] == "still_detected"


def test_rescan_verifies_fix():
    data = load_demo_data()
    source = ScanSource(type="demo", label="demo")
    first, _ = asyncio.run(run_scan(parse_dependency_tree(data, "d.json", []), mode="demo",
                                    source=source, workspace="w" * 20, demo_data=data))
    fixed = copy.deepcopy(data)

    def bump(nodes):
        for n in nodes:
            if n["name"] == "@hyron-demo/url-parser":
                n["version"] = "1.4.5"
            bump(n.get("dependencies", []))
    for p in fixed["projects"]:
        bump(p["dependencies"])
    second, _ = asyncio.run(run_scan(parse_dependency_tree(fixed, "d.json", []), mode="demo",
                                     source=source, workspace="w" * 20, demo_data=fixed))
    assert second.previous_scan_id == first.scan_id
    assert [r.package for r in second.resolved_since_previous] == ["@hyron-demo/url-parser"]
    assert second.summary.vulnerable_packages == 2


def test_live_scan_failure_is_not_reported_as_success(client, no_network):
    files = {"files": ("requirements.txt", b"flask==2.0.1\nrequests==2.25.0\n")}
    r = client.post("/api/scan", headers=WS_A, files=files)
    assert r.status_code == 201
    report = r.json()
    assert report["status"] == "verification_failed"
    assert "NOT" in report["status_detail"] or "not" in report["status_detail"]
    assert report["summary"]["scanned_packages"] == 0 and report["summary"]["unscanned_packages"] == 2
    osv = next(s for s in report["data_sources"] if s["name"] == "OSV.dev")
    assert osv["status"] == "unavailable"
    graph = client.get(f"/api/graph/{report['scan_id']}", headers=WS_A).json()
    assert {n["status"] for n in graph["nodes"] if n["type"] == "package"} == {"unscanned"}
    explain = client.post(f"/api/reports/{report['scan_id']}/explain", headers=WS_A).json()
    assert "no result from this scan is verified" in explain["explanation"]


def test_pr_draft(client):
    scan = client.post("/api/demo", headers=WS_A).json()
    url = f"/api/reports/{scan['scan_id']}/remediation/pr-draft"
    draft = client.post(url, headers=WS_A, json={"step_key": scan["patch_plan"][0]["step_key"]}).json()
    assert draft["branch"] == "hyron/upgrade-hyron-demo-url-parser-1.4.5"
    assert "Simulated demo data" in draft["body"] and "- [ ]" in draft["body"]
    no_fix = next(step["step_key"] for step in scan["patch_plan"] if step["fix_status"] == "no_fix_known")
    assert client.post(url, headers=WS_A, json={"step_key": no_fix}).status_code == 409


def test_explain_unknown_finding(client):
    scan = client.post("/api/demo", headers=WS_A).json()
    r = client.post(f"/api/reports/{scan['scan_id']}/explain", headers=WS_A, json={"finding_id": "nope"})
    assert r.status_code == 404


def test_website_requires_acknowledgement(client):
    r = client.post("/api/scan/website", json={"url": "https://example.com"})
    assert r.status_code == 422
    r = client.post("/api/scan/website", json={"url": "http://127.0.0.1", "acknowledge_passive": True})
    assert r.status_code == 422 and "private" in r.json()["detail"]


def test_repository_scan_end_to_end(client, monkeypatch):
    sha = "b" * 40
    lock = b'{"lockfileVersion":3,"packages":{"":{"name":"shop","dependencies":{"left-pad":"1.0.0"}},' \
           b'"node_modules/left-pad":{"version":"1.0.0"}}}'

    def gh(request):
        p = request.url.path
        if p == "/repos/acme/shop":
            return httpx.Response(200, json={"name": "shop", "full_name": "acme/shop", "private": False,
                                             "default_branch": "main", "owner": {"login": "acme"}})
        if p == "/repos/acme/shop/branches/main":
            return httpx.Response(200, json={"commit": {"sha": sha}})
        if p == "/repos/acme/shop/branches":
            return httpx.Response(200, json=[{"name": "main"}])
        if p == f"/repos/acme/shop/git/trees/{sha}":
            return httpx.Response(200, json={"tree": [{"path": "package-lock.json", "type": "blob", "size": 99}]})
        if p == "/repos/acme/shop/contents/package-lock.json":
            return httpx.Response(200, content=lock)
        return httpx.Response(404)

    def osv(request):
        if request.url.path.endswith("/querybatch"):
            return httpx.Response(200, json={"results": [{}]})
        return httpx.Response(404)

    monkeypatch.setattr(github_service, "new_client", lambda: httpx.AsyncClient(
        transport=httpx.MockTransport(gh), base_url=github_service.GITHUB_API))
    monkeypatch.setattr(osv_service, "new_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(osv)))

    v = client.post("/api/repositories/validate", json={"url": "https://github.com/acme/shop"})
    assert v.status_code == 200 and v.json()["manifests"] == ["package-lock.json"]
    r = client.post("/api/scan/repository", headers=WS_A, json={"url": "https://github.com/acme/shop"})
    assert r.status_code == 201
    report = r.json()
    assert report["status"] == "completed" and report["source"]["commit"] == sha
    assert report["summary"]["total_findings"] == 0
    assert report["data_sources"][0]["name"] == "GitHub API"
    assert client.post("/api/repositories/validate", json={"url": "https://evil.com/x/y"}).status_code == 422


def test_rate_limit(client, monkeypatch):
    from services.security import SCAN_LIMITER
    monkeypatch.setattr(SCAN_LIMITER, "limit", 2)
    for _ in range(2):
        client.post("/api/scan/website", json={"url": "https://example.com"})
    r = client.post("/api/scan/website", json={"url": "https://example.com"})
    assert r.status_code == 429 and "Retry-After" in r.headers
