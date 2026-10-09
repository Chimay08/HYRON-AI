"""Passive, read-only inspection of a public web page.

What it does: one GET of the page (plus up to 3 validated redirects), then
looks at response headers and HTML for observable technologies and
frontend library versions in public asset URLs. Versioned npm libraries
are checked against OSV.dev and reported as *potential exposures*.

What it does NOT do: crawl, brute-force paths, send payloads, probe
backends, or claim confirmed vulnerabilities. A URL cannot reveal a
site's private/backend dependencies.

SSRF protection: http/https only, default ports only, no embedded
credentials, every resolved address must be globally routable, redirects
are re-validated hop by hop and never followed automatically. Residual
risk: DNS could change between validation and connection (rebinding);
deployments should also restrict egress at the network layer.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import uuid
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Awaitable, Callable
from urllib.parse import urljoin, urlsplit

import httpx

from schemas.scan_result import DetectedTechnology, PotentialExposure, WebsiteReport
from schemas.vulnerability import DataSource
from services import osv_service
from services.osv_service import OSVQuery
from services.vulnerability_scanner import ExploitIntel, PackageRef, normalize_record

MAX_PAGE_BYTES = 2_000_000
MAX_REDIRECTS = 3
TIMEOUT = httpx.Timeout(10.0, connect=5.0)

NOTICE = (
    "Passive inspection only. 'Technology detected' means it was observed in public headers or markup. "
    "'Potential exposure' means a library version seen in a public asset URL matches an OSV advisory - it is "
    "NOT a confirmed vulnerability. Confirmed package vulnerabilities require a manifest/lockfile or repository scan."
)
LIMITATIONS = [
    "Only the single page requested (and its redirects) was fetched; no crawling or active testing was performed.",
    "Backend and server-side dependencies are not observable from a URL.",
    "Versions inferred from asset file names/CDN paths may be wrong (renamed, self-hosted or patched files).",
    "A library being present does not mean the vulnerable code path is used or reachable.",
    "Active security assessments require explicit written authorization from the site owner and are out of scope.",
]

Resolver = Callable[[str, int], Awaitable[list[str]]]


class WebsiteError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.message, self.status = message, status


# ------------------------------------------------------------------- SSRF --

async def _system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


def _is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip.split("%")[0])
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


async def validate_public_url(url: str, resolver: Resolver = _system_resolver) -> str:
    raw = (url or "").strip()
    if len(raw) > 500:
        raise WebsiteError("URL is too long", 422)
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise WebsiteError("Only http:// and https:// URLs are allowed", 422)
    if parts.username or parts.password:
        raise WebsiteError("URLs with embedded credentials are not allowed", 422)
    host = parts.hostname
    if not host:
        raise WebsiteError("URL has no host name", 422)
    try:
        port = parts.port
    except ValueError as exc:
        raise WebsiteError("Invalid port", 422) from exc
    if port not in (None, 80, 443):
        raise WebsiteError("Only the default web ports (80/443) are allowed", 422)
    if host.lower() in ("localhost",) or host.lower().endswith((".localhost", ".local", ".internal")):
        raise WebsiteError("Local and internal host names are not allowed", 422)
    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        try:
            addresses = await resolver(host, port or (443 if parts.scheme == "https" else 80))
        except OSError as exc:
            raise WebsiteError("Host name could not be resolved", 422) from exc
    if not addresses or not all(_is_public(a) for a in addresses):
        raise WebsiteError("The host resolves to a private, loopback or reserved address - refusing to connect", 422)
    return parts._replace(fragment="").geturl()


async def fetch_page(url: str, client: httpx.AsyncClient, resolver: Resolver = _system_resolver
                     ) -> tuple[str, httpx.Response, bytes]:
    current = await validate_public_url(url, resolver)
    for _ in range(MAX_REDIRECTS + 1):
        try:
            async with client.stream("GET", current, headers={"Accept": "text/html,*/*;q=0.5"}) as resp:
                if resp.is_redirect:
                    location = resp.headers.get("location")
                    if not location:
                        raise WebsiteError("Redirect without a location", 502)
                    current = await validate_public_url(urljoin(current, location), resolver)
                    continue
                body = b""
                async for chunk in resp.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_PAGE_BYTES:
                        body = body[:MAX_PAGE_BYTES]
                        break
                return current, resp, body
        except httpx.TimeoutException as exc:
            raise WebsiteError("The website did not respond in time", 504) from exc
        except httpx.HTTPError as exc:
            raise WebsiteError("Could not connect to the website", 502) from exc
    raise WebsiteError(f"Too many redirects (more than {MAX_REDIRECTS})", 502)


# -------------------------------------------------------------- detection --

class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.assets: list[str] = []
        self.generator: str | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): v for k, v in attrs if v}
        if tag == "script" and a.get("src"):
            self.assets.append(a["src"])
        elif tag == "link" and a.get("href") and "stylesheet" in (a.get("rel") or "").lower():
            self.assets.append(a["href"])
        elif tag == "meta" and (a.get("name") or "").lower() == "generator" and a.get("content"):
            self.generator = a["content"][:120]


_CDN_NPM = re.compile(r"(?:cdn\.jsdelivr\.net/npm|unpkg\.com)/((?:@[\w.-]+/)?[\w.-]+)@(\d+\.\d+\.\d+[\w.+-]*)", re.I)
_CDNJS = re.compile(r"cdnjs\.cloudflare\.com/ajax/libs/([\w.-]+)/(\d+\.\d+\.\d+[\w.+-]*)/", re.I)
_FILE_LIB = re.compile(
    r"/(jquery-ui|jquery|bootstrap|angular|lodash|moment|vue|react-dom|react|handlebars|underscore|d3|axios|"
    r"dompurify|knockout|backbone|ember|chart|swiper|select2)[.-]v?(\d+\.\d+\.\d+)(?:[.-]min)?\.(?:js|css)",
    re.I,
)
_NPM_ALIASES = {
    "twitter-bootstrap": "bootstrap", "jqueryui": "jquery-ui", "chart": "chart.js", "chart.js": "chart.js",
    "lodash.js": "lodash", "underscore.js": "underscore", "moment.js": "moment", "angular.js": "angular",
    "handlebars.js": "handlebars", "backbone.js": "backbone", "knockout": "knockout", "ember.js": "ember-source",
    "ember": "ember-source",
}
_MARKERS = [
    (re.compile(r'ng-version="(\d+\.\d+\.\d+)"'), "Angular", "Frontend framework", "@angular/core"),
    (re.compile(r"__NEXT_DATA__|/_next/static/"), "Next.js", "Frontend framework", None),
    (re.compile(r"/_nuxt/"), "Nuxt", "Frontend framework", None),
    (re.compile(r"wp-content/|wp-includes/"), "WordPress", "CMS", None),
    (re.compile(r"data-reactroot|__REACT_DEVTOOLS"), "React", "Frontend library", None),
    (re.compile(r"\sdata-v-[0-9a-f]{6,}"), "Vue.js", "Frontend library", None),
    (re.compile(r"___gatsby"), "Gatsby", "Static site generator", None),
    (re.compile(r"Shopify\.theme|cdn\.shopify\.com"), "Shopify", "E-commerce platform", None),
    (re.compile(r"drupal-settings-json|/sites/default/files/"), "Drupal", "CMS", None),
]
_HEADERS = {
    "server": "Web server", "x-powered-by": "Application framework", "x-generator": "Generator",
    "x-aspnet-version": "ASP.NET runtime", "x-aspnetmvc-version": "ASP.NET MVC", "x-drupal-cache": "CMS",
}


def _split_product(value: str) -> tuple[str, str | None]:
    m = re.match(r"^\s*([A-Za-z][\w .-]*?)[/ ]v?(\d+(?:\.\d+){1,3})", value)
    return (m.group(1).strip(), m.group(2)) if m else (value.strip()[:60], None)


def detect_technologies(headers: dict[str, str], html: str, page_url: str) -> list[DetectedTechnology]:
    found: dict[tuple[str, str | None], DetectedTechnology] = {}

    def add(t: DetectedTechnology) -> None:
        found.setdefault((t.name.lower(), t.version), t)

    for header, category in _HEADERS.items():
        value = headers.get(header)
        if value:
            name, version = _split_product(value)
            add(DetectedTechnology(name=name, version=version, category=category,
                                   evidence=f"HTTP header {header}: {value[:80]}", confidence="high"))

    parser = _Collector()
    try:
        parser.feed(html)
    except Exception:  # malformed markup is common; keep what was collected
        pass
    if parser.generator:
        name, version = _split_product(parser.generator)
        add(DetectedTechnology(name=name, version=version, category="Generator / CMS",
                               evidence=f'<meta name="generator" content="{parser.generator}">', confidence="high"))

    for src in parser.assets[:300]:
        absolute = urljoin(page_url, src)
        for regex, confidence in ((_CDN_NPM, "high"), (_CDNJS, "medium"), (_FILE_LIB, "medium")):
            m = regex.search(absolute)
            if m:
                lib, version = m.group(1), m.group(2)
                npm = _NPM_ALIASES.get(lib.lower(), lib.lower())
                add(DetectedTechnology(
                    name=lib, version=version, category="Frontend library",
                    evidence=f"asset URL {absolute[:160]}", confidence=confidence, npm_package=npm,
                ))
                break

    for regex, name, category, npm in _MARKERS:
        m = regex.search(html)
        if m:
            version = m.group(1) if m.groups() else None
            add(DetectedTechnology(
                name=name, version=version, category=category,
                evidence=f"page markup contains '{m.group(0)[:60]}'",
                confidence="medium" if version else "low", npm_package=npm if version else None,
            ))
    versioned = {name for (name, version) in found if version}
    techs = [t for (name, version), t in found.items() if version or name not in versioned]
    return sorted(techs, key=lambda t: (t.category, t.name.lower()))


# ------------------------------------------------------------------- main --

async def inspect_website(url: str, client: httpx.AsyncClient | None = None,
                          resolver: Resolver = _system_resolver) -> WebsiteReport:
    own = client is None
    client = client or httpx.AsyncClient(
        timeout=TIMEOUT, follow_redirects=False, headers={"User-Agent": osv_service.USER_AGENT},
    )
    try:
        final_url, resp, body = await fetch_page(url, client, resolver)
        content_type = resp.headers.get("content-type", "")
        html = body.decode(resp.encoding or "utf-8", errors="replace") if "html" in content_type or not content_type else ""
        headers = {k.lower(): v for k, v in resp.headers.items()}
        techs = detect_technologies(headers, html, final_url)

        versioned = [t for t in techs if t.npm_package and t.version]
        exposures: list[PotentialExposure] = []
        sources: list[DataSource] = [DataSource(
            name="Target website (passive GET)", url=final_url, status="ok",
            retrieved_at=osv_service.now_iso(), detail=f"HTTP {resp.status_code}, {len(body)} bytes",
        )]
        status, detail = "completed", "Passive inspection completed."
        if versioned:
            queries = [OSVQuery(f"{t.npm_package}@{t.version}", "npm", t.npm_package, t.version) for t in versioned]
            osv = await osv_service.query_osv(client, queries)
            sources.append(osv.source)
            intel = ExploitIntel(kev=None)
            for t in versioned:
                ref = PackageRef(f"{t.npm_package}@{t.version}", "npm", t.npm_package, t.version)
                for vid in osv.ids.get(ref.node_id, []):
                    rec = osv.records.get(vid)
                    m = normalize_record(rec, ref, server_matched=True, intel=intel) if rec else None
                    if m:
                        exposures.append(PotentialExposure(
                            technology=t.name, npm_package=t.npm_package, version=t.version,
                            evidence=t.evidence, vulnerability=m.info,
                        ))
            if osv.source.status == "unavailable":
                status, detail = "verification_failed", "Technologies detected, but the OSV.dev advisory check failed."
            elif osv.errors:
                status, detail = "completed_with_gaps", "Some detected library versions could not be checked against OSV.dev."
        else:
            sources.append(DataSource(name="OSV.dev", status="not_used",
                                      detail="no versioned npm libraries observed in public assets"))
        exposures.sort(key=lambda e: -(e.vulnerability.cvss_score or 0))
        return WebsiteReport(
            scan_id=uuid.uuid4().hex[:12],
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            url=url, final_url=final_url, http_status=resp.status_code,
            status=status, status_detail=detail, technologies=techs,
            potential_exposures=exposures, notice=NOTICE, limitations=LIMITATIONS, data_sources=sources,
        )
    finally:
        if own:
            await client.aclose()
