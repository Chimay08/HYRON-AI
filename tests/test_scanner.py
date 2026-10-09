import asyncio

import httpx
import pytest

from services import versioning
from services.osv_service import EPSS_URL, KEV_URL, OSV_API
from services.vulnerability_scanner import (
    ExploitIntel, PackageRef, cvss3_base_score, normalize_record, scan_demo, scan_live,
)

# ---------------------------------------------------------------- versions

@pytest.mark.parametrize("eco,a,b,expected", [
    ("npm", "1.4.2", "1.4.10", -1),
    ("npm", "2.0.0-rc.1", "2.0.0", -1),
    ("npm", "2.0.0-alpha.2", "2.0.0-alpha.10", -1),
    ("PyPI", "2.11.2", "2.11.10", -1),
    ("PyPI", "1.0rc1", "1.0", -1),
    ("Maven", "2.9.10", "2.9.10.3", -1),
    ("Maven", "1.0", "1.0.0", 0),
    ("Maven", "1.0-rc1", "1.0", -1),
    ("Maven", "2.17.0", "2.9.10", 1),
    ("Maven", "1.2.3.Final", "1.2.3", 0),
])
def test_version_compare(eco, a, b, expected):
    assert versioning.compare(eco, a, b) == expected


ENTRY = {
    "package": {"ecosystem": "npm", "name": "url-parser"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.4.5"},
                                               {"introduced": "2.0.0"}, {"fixed": "2.1.1"}]}],
}


@pytest.mark.parametrize("version,affected,fix", [
    ("0.9.0", False, None),
    ("1.0.0", True, "1.4.5"),
    ("1.4.2", True, "1.4.5"),
    ("1.4.5", False, None),
    ("2.0.3", True, "2.1.1"),
    ("2.1.1", False, None),
])
def test_range_evaluation(version, affected, fix):
    assert versioning.is_affected("npm", version, ENTRY) is affected
    assert versioning.fixed_version_for("npm", version, ENTRY) == fix


def test_last_affected_and_explicit_versions():
    entry = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1.2.0"}]}]}
    assert versioning.is_affected("PyPI", "1.2.0", entry) is True
    assert versioning.is_affected("PyPI", "1.2.1", entry) is False
    assert versioning.fixed_version_for("PyPI", "1.0", entry) is None  # no fix event -> unknown
    assert versioning.is_affected("npm", "3.0.0", {"versions": ["3.0.0"]}) is True
    assert versioning.is_affected("npm", "3.0.1", {"versions": ["3.0.0"]}) is False
    assert versioning.is_affected("npm", "3.0.1", {"ranges": [{"type": "GIT", "events": []}]}) is None


@pytest.mark.parametrize("eco,declared,candidate,expected", [
    ("npm", "^1.4.0", "1.4.5", True),
    ("npm", "^1.4.0", "2.0.0", False),
    ("npm", "~1.4.0", "1.5.0", False),
    ("npm", "^0.9.0", "0.9.4", True),
    ("npm", "1.4.2", "1.4.5", False),
    ("PyPI", ">=2.25.0,<3", "2.31.0", True),
    ("PyPI", "==2.25.0", "2.31.0", False),
    ("Maven", "2.14.1", "2.17.1", False),
    ("npm", "latest", "1.0.0", None),
])
def test_constraint_allows(eco, declared, candidate, expected):
    assert versioning.constraint_allows(eco, declared, candidate) is expected


# ------------------------------------------------------------------- CVSS

@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", None),
    ("garbage", None),
])
def test_cvss3_base_score(vector, score):
    assert cvss3_base_score(vector) == score


# ---------------------------------------------------------- normalisation

def record(**overrides):
    rec = {
        "id": "GHSA-test-0001", "aliases": ["CVE-2099-0001"], "summary": "test issue",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [ENTRY],
    }
    rec.update(overrides)
    return rec


REF = PackageRef("npm:url-parser@1.4.2", "npm", "url-parser", "1.4.2")


def test_normalize_matches_and_enriches():
    intel = ExploitIntel(kev={"CVE-2099-0001"}, epss={"CVE-2099-0001": 0.5})
    m = normalize_record(record(), REF, server_matched=False, intel=intel)
    assert m is not None
    v = m.info
    assert v.cvss_score == 9.8 and v.cvss_source == "vector" and v.severity_label == "CRITICAL"
    assert v.fixed_version == "1.4.5" and v.in_kev is True and v.epss == 0.5
    assert v.match_basis == "local_range_check" and v.source == "OSV.dev"
    assert v.source_url == "https://osv.dev/vulnerability/GHSA-test-0001"


def test_normalize_requires_version_in_range():
    ref = PackageRef("npm:url-parser@1.4.5", "npm", "url-parser", "1.4.5")
    assert normalize_record(record(), ref, server_matched=False, intel=ExploitIntel()) is None


def test_normalize_requires_same_ecosystem_and_name():
    other_eco = record(affected=[{**ENTRY, "package": {"ecosystem": "PyPI", "name": "url-parser"}}])
    other_name = record(affected=[{**ENTRY, "package": {"ecosystem": "npm", "name": "url-parser2"}}])
    assert normalize_record(other_eco, REF, server_matched=True, intel=ExploitIntel()) is None
    assert normalize_record(other_name, REF, server_matched=True, intel=ExploitIntel()) is None


def test_normalize_handles_missing_data():
    rec = record(severity=[], database_specific={"severity": "MODERATE"}, aliases=[])
    m = normalize_record(rec, REF, server_matched=False, intel=ExploitIntel(kev=None))
    assert m.info.cvss_score == 5.5 and m.info.cvss_source == "severity_label" and m.info.severity_label == "MEDIUM"
    assert m.info.in_kev is None and m.info.epss is None

    bare = record(severity=[], aliases=[])
    m = normalize_record(bare, REF, server_matched=False, intel=ExploitIntel(kev=set()))
    assert m.info.cvss_score is None and m.info.cvss_source == "unknown" and m.info.in_kev is False


def test_server_match_kept_when_local_check_inconclusive():
    rec = record(affected=[{"package": {"ecosystem": "npm", "name": "url-parser"},
                            "ranges": [{"type": "GIT", "events": [{"introduced": "abc"}]}]}])
    assert normalize_record(rec, REF, server_matched=False, intel=ExploitIntel()) is None
    m = normalize_record(rec, REF, server_matched=True, intel=ExploitIntel())
    assert m is not None and m.info.match_basis == "osv_reported"


def test_scan_demo_uses_synthetic_records():
    from services.pipeline import load_demo_data
    data = load_demo_data()
    refs = [
        PackageRef("a", "npm", "@hyron-demo/url-parser", "1.4.2"),
        PackageRef("b", "npm", "@hyron-demo/http-client", "2.3.0"),  # only a 1.x range exists
    ]
    out = scan_demo(refs, data)
    assert list(out.matches) == ["a"]
    info = out.matches["a"][0].info
    assert info.id == "HYRON-DEMO-2026-0001" and info.synthetic and info.in_kev is True
    assert info.source == "Synthetic demo dataset" and info.source_url is None
    assert out.sources[0].status == "synthetic"


# ------------------------------------------------------ live (mocked HTTP)

def mock_transport(osv_ok=True, kev_ok=True):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        calls.append(url)
        if url == f"{OSV_API}/querybatch":
            if not osv_ok:
                return httpx.Response(503)
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-test-0001"}]}, {}]})
        if url == f"{OSV_API}/vulns/GHSA-test-0001":
            return httpx.Response(200, json=record())
        if url == KEV_URL:
            return httpx.Response(200, json={"vulnerabilities": [{"cveID": "CVE-2099-0001"}]}) if kev_ok \
                else httpx.Response(500)
        if url.startswith(EPSS_URL):
            return httpx.Response(200, json={"data": [{"cve": "CVE-2099-0001", "epss": "0.42"}]})
        return httpx.Response(404)

    return httpx.MockTransport(handler), calls


def run_live(transport):
    refs = [REF, PackageRef("npm:safe@1.0.0", "npm", "safe", "1.0.0")]

    async def go():
        async with httpx.AsyncClient(transport=transport) as client:
            return await scan_live(refs, client=client)
    return asyncio.run(go())


def test_scan_live_with_mocked_apis():
    transport, calls = mock_transport()
    out = run_live(transport)
    assert list(out.matches) == [REF.node_id]
    v = out.matches[REF.node_id][0].info
    assert v.in_kev is True and v.epss == 0.42 and v.match_basis == "local_range_check"
    assert not out.errors
    assert {s.name: s.status for s in out.sources} == {"OSV.dev": "ok", "CISA KEV": "ok", "FIRST EPSS": "ok"}
    # second scan is served from cache: no new OSV detail / KEV requests
    n = len(calls)
    run_live(transport)
    assert not any("/vulns/" in c or c == KEV_URL for c in calls[n:])


def test_scan_live_osv_outage_is_a_coverage_gap():
    transport, _ = mock_transport(osv_ok=False)
    out = run_live(transport)
    assert not out.matches
    assert set(out.errors) == {REF.node_id, "npm:safe@1.0.0"}
    assert "OSV.dev query failed" in out.errors[REF.node_id]
    assert out.sources[0].name == "OSV.dev" and out.sources[0].status == "unavailable"


def test_scan_live_kev_outage_marks_unknown():
    transport, _ = mock_transport(kev_ok=False)
    out = run_live(transport)
    v = out.matches[REF.node_id][0].info
    assert v.in_kev is None
    kev = next(s for s in out.sources if s.name == "CISA KEV")
    assert kev.status == "unavailable" and "unknown" in kev.detail


def test_scan_live_rate_limited_and_malformed():
    def limited(request):
        return httpx.Response(429)

    out = run_live(httpx.MockTransport(limited))
    assert "rate limited" in out.errors[REF.node_id]

    def malformed(request):
        return httpx.Response(200, json={"results": "nope"})

    out = run_live(httpx.MockTransport(malformed))
    assert set(out.errors) == {REF.node_id, "npm:safe@1.0.0"} and not out.matches
