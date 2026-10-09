"""Read-only GitHub repository access for dependency scanning.

* Only https://github.com/<owner>/<repo> URLs are accepted and every request
  goes to the fixed host api.github.com - user input never becomes a host,
  which rules out SSRF through this path.
* Public repositories work anonymously (60 requests/hour per IP). Private
  repositories need a server-side GITHUB_TOKEN (fine-grained, read-only
  "Contents" permission). The token is never returned, logged or sent to the
  browser. Users are never asked for a password.
* Repository files are downloaded as data and parsed; nothing is executed.
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from urllib.parse import quote

import httpx

from schemas.scan_result import RepositoryInfo
from services.manifest_parser import is_repository_manifest, max_bytes_for

GITHUB_API = "https://api.github.com"
TIMEOUT = httpx.Timeout(15.0, connect=5.0)
MAX_MANIFESTS = 30
MAX_PATH_DEPTH = 6
SKIP_DIRS = {"node_modules", "vendor", ".git", "dist", "build", "target", ".venv", "venv", "site-packages",
             "__pycache__", "bower_components", "third_party", "fixtures", "testdata"}

_URL_RE = re.compile(
    r"^https://(?:www\.)?github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/"
    r"(?P<repo>[A-Za-z0-9._-]{1,100}?)(?:\.git)?(?:/tree/(?P<branch>[^?#]+?))?/?$"
)
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")


class GitHubError(Exception):
    """Error with a user-safe message and the HTTP status the API should return."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.message, self.status = message, status


@dataclass
class RepoRef:
    owner: str
    repo: str
    branch: str | None


def parse_repo_url(url: str, branch: str | None = None) -> RepoRef:
    m = _URL_RE.match((url or "").strip())
    if not m:
        raise GitHubError("Enter a GitHub repository URL like https://github.com/owner/repo", 422)
    ref_branch = (branch or m.group("branch") or "").strip() or None
    if ref_branch and (not _BRANCH_RE.match(ref_branch) or ".." in ref_branch or ref_branch.startswith("/")):
        raise GitHubError("Invalid branch name", 422)
    repo = m.group("repo")
    if repo in (".", ".."):
        raise GitHubError("Invalid repository name", 422)
    return RepoRef(owner=m.group("owner"), repo=repo, branch=ref_branch)


def token_configured() -> bool:
    return bool(os.getenv("GITHUB_TOKEN"))


def new_client() -> httpx.AsyncClient:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "HYRON-AI/0.2",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.AsyncClient(base_url=GITHUB_API, timeout=TIMEOUT, headers=headers, follow_redirects=False)


def _raise_for(resp: httpx.Response, what: str) -> None:
    if resp.status_code < 400:
        return
    if resp.status_code in (403, 429) and (
        resp.headers.get("x-ratelimit-remaining") == "0" or resp.status_code == 429
    ):
        reset = resp.headers.get("x-ratelimit-reset")
        hint = "" if token_configured() else " Configure GITHUB_TOKEN on the server for a higher limit."
        raise GitHubError(
            f"GitHub API rate limit reached{f' (resets at unix time {reset})' if reset else ''}.{hint}", 429
        )
    if resp.status_code == 401:
        raise GitHubError("GitHub rejected the server's credentials (check GITHUB_TOKEN).", 502)
    if resp.status_code in (403, 404):
        hint = "" if token_configured() else " Private repositories need a server-side GITHUB_TOKEN."
        raise GitHubError(f"{what} not found or not accessible.{hint}", 404)
    raise GitHubError(f"GitHub API error while reading {what} (HTTP {resp.status_code}).", 502)


async def _get(client: httpx.AsyncClient, path: str, what: str, **kw) -> httpx.Response:
    try:
        resp = await client.get(path, **kw)
    except httpx.TimeoutException as exc:
        raise GitHubError("GitHub API timed out.", 504) from exc
    except httpx.HTTPError as exc:
        raise GitHubError("Could not reach the GitHub API.", 502) from exc
    _raise_for(resp, what)
    return resp


def _wanted(path: str) -> bool:
    parts = path.split("/")
    return (
        len(parts) <= MAX_PATH_DEPTH
        and not any(p in SKIP_DIRS or p.startswith(".") for p in parts[:-1])
        and is_repository_manifest(path)
    )


async def inspect_repository(url: str, branch: str | None = None,
                             client: httpx.AsyncClient | None = None) -> RepositoryInfo:
    ref = parse_repo_url(url, branch)
    own = client is None
    client = client or new_client()
    try:
        base = f"/repos/{quote(ref.owner)}/{quote(ref.repo)}"
        meta = (await _get(client, base, "Repository")).json()
        default_branch = meta.get("default_branch") or "main"
        target = ref.branch or default_branch
        branch_data = (await _get(client, f"{base}/branches/{quote(target, safe='')}", f"Branch '{target}'")).json()
        commit = branch_data.get("commit", {}).get("sha")
        if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise GitHubError("Unexpected response from GitHub (branch commit).", 502)
        branches_resp = await _get(client, f"{base}/branches", "Branch list", params={"per_page": 100})
        branches = [b.get("name") for b in branches_resp.json() if isinstance(b, dict) and isinstance(b.get("name"), str)]
        tree = (await _get(client, f"{base}/git/trees/{commit}", "Repository tree", params={"recursive": "1"})).json()

        manifests, skipped = [], []
        for entry in tree.get("tree") or []:
            if not isinstance(entry, dict) or entry.get("type") != "blob" or not isinstance(entry.get("path"), str):
                continue
            path = entry["path"]
            if not _wanted(path):
                continue
            if int(entry.get("size") or 0) > max_bytes_for(path):
                skipped.append(f"{path} (too large)")
                continue
            manifests.append(path)
        manifests.sort(key=lambda p: (p.count("/"), p))
        if len(manifests) > MAX_MANIFESTS:
            skipped += [f"{p} (over {MAX_MANIFESTS}-file limit)" for p in manifests[MAX_MANIFESTS:]]
            manifests = manifests[:MAX_MANIFESTS]
        return RepositoryInfo(
            owner=meta.get("owner", {}).get("login") or ref.owner,
            repo=meta.get("name") or ref.repo,
            full_name=meta.get("full_name") or f"{ref.owner}/{ref.repo}",
            html_url=f"https://github.com/{ref.owner}/{ref.repo}",
            private=bool(meta.get("private")),
            default_branch=default_branch, branch=target, commit=commit,
            branches=branches or [target], manifests=manifests, skipped=skipped,
            truncated=bool(tree.get("truncated")),
            auth="token" if token_configured() else "anonymous",
        )
    finally:
        if own:
            await client.aclose()


async def fetch_manifests(info: RepositoryInfo, client: httpx.AsyncClient | None = None) -> list[tuple[str, bytes]]:
    """Download the manifest files found by inspect_repository at its pinned commit."""
    own = client is None
    client = client or new_client()
    sem = asyncio.Semaphore(6)
    base = f"/repos/{quote(info.owner)}/{quote(info.repo)}/contents"

    async def one(path: str) -> tuple[str, bytes]:
        async with sem:
            resp = await _get(
                client, f"{base}/{quote(path)}", f"File '{path}'",
                params={"ref": info.commit}, headers={"Accept": "application/vnd.github.raw+json"},
            )
            return path, resp.content[: max_bytes_for(path) + 1]

    try:
        return list(await asyncio.gather(*(one(p) for p in info.manifests)))
    finally:
        if own:
            await client.aclose()
