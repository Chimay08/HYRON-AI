"""Clients for OSV.dev, CISA KEV and FIRST EPSS, with an in-memory TTL cache.

Only the minimum data leaves the server: {ecosystem, package, version}
for OSV and CVE identifiers for EPSS. The KEV catalogue is downloaded whole.
External responses are treated as untrusted and validated before use.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from schemas.vulnerability import DataSource

OSV_API = "https://api.osv.dev/v1"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

HTTP_TIMEOUT = httpx.Timeout(15.0, connect=5.0)
USER_AGENT = "HYRON-AI/0.2 (+supply-chain security prototype)"
OSV_BATCH = 500
OSV_MAX_PAGES = 10
EPSS_BATCH = 50
DETAIL_CONCURRENCY = 8
OSV_TTL = 6 * 3600
INTEL_TTL = 12 * 3600


def now_iso(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or time.time(), timezone.utc).isoformat(timespec="seconds")


class TTLCache:
    def __init__(self) -> None:
        self._data: dict[str, tuple[float, Any]] = {}

    def get(self, key: str, ttl: float) -> tuple[Any, bool, float] | None:
        """Return (value, is_fresh, stored_at) or None if never cached."""
        hit = self._data.get(key)
        if hit is None:
            return None
        ts, value = hit
        return value, (time.time() - ts) < ttl, ts

    def set(self, key: str, value: Any) -> None:
        self._data[key] = (time.time(), value)

    def clear(self) -> None:
        self._data.clear()


CACHE = TTLCache()


def new_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT}, follow_redirects=False)


async def get_json(client: httpx.AsyncClient, method: str, url: str, **kw) -> Any:
    resp = await client.request(method, url, **kw)
    resp.raise_for_status()
    return resp.json()


def describe_error(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        if code == 429:
            return "rate limited (HTTP 429)"
        return f"HTTP {code}"
    if isinstance(exc, httpx.TimeoutException):
        return "timed out"
    if isinstance(exc, httpx.HTTPError):
        return "network error"
    return "malformed response"


# --------------------------------------------------------------------- OSV --

@dataclass
class OSVQuery:
    key: str
    ecosystem: str
    name: str
    version: str


@dataclass
class OSVResult:
    ids: dict[str, list[str]] = field(default_factory=dict)      # query key -> vuln ids
    records: dict[str, dict] = field(default_factory=dict)       # vuln id -> record
    errors: dict[str, str] = field(default_factory=dict)         # query key -> reason
    warnings: list[str] = field(default_factory=list)
    source: DataSource | None = None


def _vuln_ids(res: dict) -> list[str]:
    return [v["id"] for v in res.get("vulns") or [] if isinstance(v, dict) and isinstance(v.get("id"), str)]


async def _fetch_remaining_pages(client: httpx.AsyncClient, q: OSVQuery, token: str, out: OSVResult) -> None:
    """Follow next_page_token for one package so long advisory lists are not cut off."""
    for _ in range(OSV_MAX_PAGES):
        body = {"package": {"name": q.name, "ecosystem": q.ecosystem}, "version": q.version, "page_token": token}
        try:
            data = await get_json(client, "POST", f"{OSV_API}/query", json=body)
            if not isinstance(data, dict):
                raise ValueError("unexpected query shape")
        except (httpx.HTTPError, ValueError) as exc:
            out.errors[q.key] = f"OSV.dev returned only part of the advisory list ({describe_error(exc)})"
            return
        out.ids[q.key] = sorted(set(out.ids[q.key]) | set(_vuln_ids(data)))
        token = data.get("next_page_token")
        if not token:
            return
    out.warnings.append(f"{q.name}: more than {OSV_MAX_PAGES} pages of OSV results; list may be incomplete")


async def query_osv(client: httpx.AsyncClient, queries: list[OSVQuery]) -> OSVResult:
    out = OSVResult()
    ok_batches = failed_batches = 0
    for start in range(0, len(queries), OSV_BATCH):
        chunk = queries[start:start + OSV_BATCH]
        body = {"queries": [
            {"package": {"name": q.name, "ecosystem": q.ecosystem}, "version": q.version} for q in chunk
        ]}
        try:
            data = await get_json(client, "POST", f"{OSV_API}/querybatch", json=body)
            results = data.get("results")
            if not isinstance(results, list) or len(results) != len(chunk):
                raise ValueError("unexpected querybatch shape")
        except (httpx.HTTPError, ValueError, AttributeError) as exc:
            failed_batches += 1
            for q in chunk:
                out.errors[q.key] = f"OSV.dev query failed ({describe_error(exc)})"
            continue
        ok_batches += 1
        for q, res in zip(chunk, results):
            res = res if isinstance(res, dict) else {}
            out.ids[q.key] = _vuln_ids(res)
            token = res.get("next_page_token")
            if token:
                await _fetch_remaining_pages(client, q, token, out)

    all_ids = sorted({i for ids in out.ids.values() for i in ids})
    sem = asyncio.Semaphore(DETAIL_CONCURRENCY)
    stale = 0

    async def fetch(vid: str) -> None:
        nonlocal stale
        cached = CACHE.get(f"osv:{vid}", OSV_TTL)
        if cached and cached[1]:
            out.records[vid] = cached[0]
            return
        async with sem:
            try:
                rec = await get_json(client, "GET", f"{OSV_API}/vulns/{vid}")
                if not isinstance(rec, dict) or rec.get("id") != vid:
                    raise ValueError("unexpected record")
                CACHE.set(f"osv:{vid}", rec)
                out.records[vid] = rec
            except (httpx.HTTPError, ValueError):
                if cached:
                    out.records[vid] = cached[0]
                    stale += 1

    await asyncio.gather(*(fetch(i) for i in all_ids))
    for key, ids in out.ids.items():
        missing = [i for i in ids if i not in out.records]
        if missing:
            out.errors.setdefault(key, f"advisory details unavailable from OSV.dev ({', '.join(missing[:3])})")
    if stale:
        out.warnings.append(f"{stale} OSV record(s) could not be refreshed; cached (stale) copies were used")

    if not queries:
        status, detail = "not_used", "no package versions to query"
    elif failed_batches and not ok_batches:
        status, detail = "unavailable", "live vulnerability check failed - results are NOT verified"
    elif failed_batches or out.errors or stale:
        status, detail = ("stale" if stale and not failed_batches else "partial"), \
            f"{len(out.errors)} package(s) could not be fully checked"
    else:
        status, detail = "ok", f"{len(queries)} package version(s) queried, {len(all_ids)} advisories retrieved"
    out.source = DataSource(name="OSV.dev", url="https://osv.dev", status=status, retrieved_at=now_iso(), detail=detail)
    return out


# --------------------------------------------------------------- KEV / EPSS --

async def fetch_kev(client: httpx.AsyncClient) -> tuple[set[str] | None, DataSource]:
    cached = CACHE.get("kev", INTEL_TTL)
    src = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    if cached and cached[1]:
        return cached[0], DataSource(name="CISA KEV", url=src, status="ok", retrieved_at=now_iso(cached[2]),
                                     detail=f"{len(cached[0])} catalogue entries (cached)")
    try:
        data = await get_json(client, "GET", KEV_URL)
        kev = {v["cveID"] for v in data["vulnerabilities"] if isinstance(v, dict) and isinstance(v.get("cveID"), str)}
        CACHE.set("kev", kev)
        return kev, DataSource(name="CISA KEV", url=src, status="ok", retrieved_at=now_iso(),
                               detail=f"{len(kev)} catalogue entries")
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        if cached:
            return cached[0], DataSource(name="CISA KEV", url=src, status="stale", retrieved_at=now_iso(cached[2]),
                                         detail=f"refresh failed ({describe_error(exc)}); using cached copy")
        return None, DataSource(name="CISA KEV", url=src, status="unavailable",
                                detail=f"download failed ({describe_error(exc)}); KEV status shown as unknown")


async def fetch_epss(client: httpx.AsyncClient, cves: list[str]) -> tuple[dict[str, float], DataSource]:
    src = "https://www.first.org/epss/"
    scores: dict[str, float] = {}
    missing: list[str] = []
    for c in cves:
        hit = CACHE.get(f"epss:{c}", INTEL_TTL)
        if hit and hit[1]:
            if hit[0] is not None:
                scores[c] = hit[0]
        else:
            missing.append(c)
    failed = 0
    for start in range(0, len(missing), EPSS_BATCH):
        chunk = missing[start:start + EPSS_BATCH]
        try:
            data = await get_json(client, "GET", EPSS_URL, params={"cve": ",".join(chunk)})
            got = {row["cve"]: float(row["epss"]) for row in data["data"]}
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            failed += len(chunk)
            for c in chunk:
                stale = CACHE.get(f"epss:{c}", INTEL_TTL)
                if stale and stale[0] is not None:
                    scores[c] = stale[0]
            continue
        for c in chunk:
            value = got.get(c)
            if value is not None and not 0.0 <= value <= 1.0:
                value = None
            CACHE.set(f"epss:{c}", value)
            if value is not None:
                scores[c] = value
    if failed and failed == len(missing) and missing and not scores:
        status, detail = "unavailable", "EPSS lookup failed; exploit probabilities unknown"
    elif failed:
        status, detail = "partial", f"{failed} of {len(cves)} CVE lookups failed"
    else:
        status, detail = "ok", f"{len(scores)} of {len(cves)} CVEs have EPSS scores"
    return scores, DataSource(name="FIRST EPSS", url=src, status=status, retrieved_at=now_iso(), detail=detail)
