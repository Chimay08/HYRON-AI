"""GitHub repository access and passive website inspection (all HTTP mocked)."""

import asyncio
import json

import httpx
import pytest

from services import github_service, website_inspector
from services.github_service import GitHubError, parse_repo_url
from services.osv_service import OSV_API
from services.website_inspector import WebsiteError, detect_technologies, validate_public_url

# ------------------------------------------------------------------ GitHub

@pytest.mark.parametrize("url,expected", [
    ("https://github.com/acme/shop", ("acme", "shop", None)),
    ("https://github.com/acme/shop.git", ("acme", "shop", None)),
    ("https://github.com/acme/shop/", ("acme", "shop", None)),
    ("https://github.com/acme/shop/tree/release/1.x", ("acme", "shop", "release/1.x")),
])
def test_parse_repo_url(url, expected):
    ref = parse_repo_url(url)
    assert (ref.owner, ref.repo, ref.branch) == expected


@pytest.mark.parametrize("url", [
    "http://github.com/acme/shop",                 # not https
    "https://gitlab.com/acme/shop",                # other host
    "https://github.com.evil.com/acme/shop",       # host spoof
    "https://github.com/acme",                     # no repo
    "https://user:pw@github.com/acme/shop",        # credentials
    "https://github.com/acme/shop?x=1",
    "file:///etc/passwd",
])
def test_parse_repo_url_rejects(url):
    with pytest.raises(GitHubError):
        parse_repo_url(url)


def test_branch_validation():
    with pytest.raises(GitHubError):
        parse_repo_url("https://github.com/acme/shop", branch="../../etc")


SHA = "a" * 40


def github_transport(tree_entries, files, *, repo_status=200, rate_limited=False):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        assert request.url.host == "api.github.com"
        if rate_limited:
            return httpx.Response(403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1700000000"})
        if path == "/repos/acme/shop":
            if repo_status != 200:
                return httpx.Response(repo_status, json={"message": "Not Found"})
            return httpx.Response(200, json={"name": "shop", "full_name": "acme/shop", "private": False,
                                             "default_branch": "main", "owner": {"login": "acme"}})
        if path == "/repos/acme/shop/branches/main":
            return httpx.Response(200, json={"name": "main", "commit": {"sha": SHA}})
        if path == "/repos/acme/shop/branches":
            return httpx.Response(200, json=[{"name": "main"}, {"name": "dev"}])
        if path == f"/repos/acme/shop/git/trees/{SHA}":
            return httpx.Response(200, json={"tree": tree_entries, "truncated": False})
        if path.startswith("/repos/acme/shop/contents/"):
            name = path.split("/contents/", 1)[1]
            assert request.url.params["ref"] == SHA
            return httpx.Response(200, content=files[name])
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def run(coro):
    return asyncio.run(coro)


def gh_client(transport):
    return httpx.AsyncClient(transport=transport, base_url=github_service.GITHUB_API)


def test_inspect_repository_finds_manifests_and_skips_noise():
    tree = [
        {"path": "package.json", "type": "blob", "size": 100},
        {"path": "package-lock.json", "type": "blob", "size": 100},
        {"path": "node_modules/x/package.json", "type": "blob", "size": 100},
        {"path": "api/requirements.txt", "type": "blob", "size": 50},
        {"path": "api/huge/poetry.lock", "type": "blob", "size": 99_000_000},
        {"path": "tsconfig.json", "type": "blob", "size": 10},
        {"path": "src", "type": "tree"},
    ]
    info = run(github_service.inspect_repository("https://github.com/acme/shop", client=gh_client(github_transport(tree, {}))))
    assert info.full_name == "acme/shop" and info.branch == "main" and info.commit == SHA
    assert info.manifests == ["package-lock.json", "package.json", "api/requirements.txt"]
    assert any("too large" in s for s in info.skipped)
    assert info.branches == ["main", "dev"] and info.auth == "anonymous"


def test_fetch_manifests_pins_commit():
    tree = [{"path": "requirements.txt", "type": "blob", "size": 20}]
    transport = github_transport(tree, {"requirements.txt": b"flask==2.0.1\n"})
    info = run(github_service.inspect_repository("https://github.com/acme/shop", client=gh_client(transport)))
    files = run(github_service.fetch_manifests(info, client=gh_client(transport)))
    assert files == [("requirements.txt", b"flask==2.0.1\n")]


def test_github_errors_are_safe():
    with pytest.raises(GitHubError) as exc:
        run(github_service.inspect_repository("https://github.com/acme/shop",
                                              client=gh_client(github_transport([], {}, repo_status=404))))
    assert exc.value.status == 404 and "GITHUB_TOKEN" in exc.value.message
    with pytest.raises(GitHubError) as exc:
        run(github_service.inspect_repository("https://github.com/acme/shop",
                                              client=gh_client(github_transport([], {}, rate_limited=True))))
    assert exc.value.status == 429 and "rate limit" in exc.value.message


# ----------------------------------------------------------------- website

async def public_resolver(host, port):
    return ["93.184.216.34"]


async def private_resolver(host, port):
    return ["10.0.0.5"]


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://10.1.2.3", "http://169.254.169.254/latest/meta-data", "http://[::1]/",
    "http://[::ffff:127.0.0.1]/", "http://localhost:80/", "ftp://example.com", "https://example.com:8443/",
    "https://user:pass@example.com/", "http://0.0.0.0/", "http://printer.local/",
])
def test_ssrf_blocked(url):
    with pytest.raises(WebsiteError):
        run(validate_public_url(url, public_resolver))


def test_private_dns_resolution_blocked():
    with pytest.raises(WebsiteError, match="private"):
        run(validate_public_url("https://intranet.example.com", private_resolver))


def test_public_url_allowed_and_normalised():
    assert run(validate_public_url("example.com/page#frag", public_resolver)) == "https://example.com/page"


HTML = """<html><head>
<meta name="generator" content="WordPress 6.4.2">
<script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/js/bootstrap.min.js"></script>
<script src="/wp-includes/js/app.js"></script>
</head><body><app-root ng-version="12.0.0"></app-root></body></html>"""


def test_detect_technologies():
    techs = detect_technologies({"server": "nginx/1.18.0", "x-powered-by": "PHP/7.4.3"}, HTML, "https://example.com/")
    by_name = {t.name.lower(): t for t in techs}
    assert by_name["nginx"].version == "1.18.0" and by_name["nginx"].confidence == "high"
    assert by_name["php"].version == "7.4.3"
    assert by_name["wordpress"].version == "6.4.2"
    assert by_name["jquery"].npm_package == "jquery" and by_name["jquery"].version == "3.4.1"
    assert by_name["lodash"].npm_package == "lodash" and by_name["lodash"].confidence == "high"
    assert by_name["twitter-bootstrap"].npm_package == "bootstrap"
    assert by_name["angular"].npm_package == "@angular/core" and by_name["angular"].version == "12.0.0"


def test_inspect_website_reports_potential_not_confirmed():
    advisory = {
        "id": "GHSA-test-jq", "summary": "XSS in jQuery", "aliases": [],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
        "affected": [{"package": {"ecosystem": "npm", "name": "jquery"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.2.0"}, {"fixed": "3.5.0"}]}]}],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == "https://example.com/":
            return httpx.Response(301, headers={"location": "https://www.example.com/"})
        if url == "https://www.example.com/":
            return httpx.Response(200, headers={"content-type": "text/html"}, text=HTML)
        if url == f"{OSV_API}/querybatch":
            queries = json.loads(request.content)["queries"]
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": "GHSA-test-jq"}]} if q["package"]["name"] == "jquery" else {} for q in queries
            ]})
        if url == f"{OSV_API}/vulns/GHSA-test-jq":
            return httpx.Response(200, json=advisory)
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    report = run(website_inspector.inspect_website("https://example.com/", client=client, resolver=public_resolver))
    assert report.final_url == "https://www.example.com/" and report.status == "completed"
    assert [e.npm_package for e in report.potential_exposures] == ["jquery"]
    assert report.potential_exposures[0].vulnerability.fixed_version == "3.5.0"
    assert report.confirmed_vulnerabilities == []
    assert "NOT a confirmed vulnerability" in report.notice


def test_redirect_to_private_address_blocked():
    def handler(request):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(WebsiteError):
        run(website_inspector.inspect_website("https://example.com/", client=client, resolver=public_resolver))
