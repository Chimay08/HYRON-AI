# HYRON AI

**See the risk. Trace the impact. Fix it.**

HYRON AI is a software supply-chain security prototype. Authorized development and security teams use it to:

- connect a GitHub repository or upload dependency files,
- find known-vulnerable package versions using real OSV.dev advisory data,
- trace which projects reach each vulnerable package, directly or transitively,
- prioritise findings with explainable evidence (CVSS, CISA KEV, FIRST EPSS, runtime context), and
- work through an ordered remediation plan.

A separate, passive **website inspection** mode reports observable frontend technologies. It is clearly separated from dependency scanning. The **demo mode** runs fully offline on clearly labelled simulated data.

> Hackathon prototype. Read [Security](#security) and [Limitations](#known-limitations) before using it on real or confidential code.

---

## Contents

- [Features](#features)
- [Stack](#stack)
- [Prerequisites](#prerequisites)
- [Install and run](#install-and-run)
- [Configuration](#configuration)
- [Testing](#testing)
- [API](#api)
- [How scanning works](#how-scanning-works)
- [HYRON Risk Score](#hyron-risk-score)
- [Remediation](#remediation)
- [Security](#security)
- [Known limitations](#known-limitations)
- [Demo instructions](#demo-instructions)
- [Project structure](#project-structure)

## Features

| Area | What works |
|---|---|
| **Scan methods** | GitHub repository (public anonymously, private with a server-side token), file upload (drag and drop, progress, validation, remove/retry), passive website inspection, offline demo |
| **Formats** | `package.json`, `package-lock.json` / `npm-shrinkwrap.json` (v1–v3), `requirements*.txt`, `pyproject.toml` (PEP 621 + Poetry), `poetry.lock`, `pom.xml`, Maven `dependency:tree` text output, HYRON dependency-tree JSON |
| **Vulnerability data** | Live OSV.dev queries, local affected-range verification, CVSS v3 scoring from vectors, CISA KEV and FIRST EPSS enrichment, caching, graceful degradation |
| **Graph** | NetworkX dependency graph and blast radius; Cytoscape.js view with zoom and pan, node details, path highlighting, filters (status, severity, ecosystem), legend, reset view, completeness notice |
| **Prioritisation** | HYRON Risk Score with severity, exploitability and exposure shown separately; missing evidence flagged and the score marked provisional |
| **Remediation** | Ordered plan, fixed versions from advisories, upgrade and verification commands, compatibility checklist, status tracking (under review / user-reported / verified by re-scan), PR draft generation |
| **Reports** | Report page with scan metadata, data-source timestamps, findings, affected projects, dependency paths, ranking and fixes, coverage gaps and limitations; JSON export; print / save as PDF; remediation report view |
| **AI Copilot** | Optional Claude explanations grounded in scan data; deterministic template explanations when no key is set |
| **UI** | React app with sidebar, top bar (breadcrumbs, quick search, scan status, demo profile), Overview dashboard with charts, Repositories, Findings, Graph, Remediation, History, Settings; responsive down to phone width |

## Stack

| Layer | Tech |
|---|---|
| Frontend | React 19, Vite, JavaScript/JSX, Tailwind CSS 4, React Router, Axios, Lucide React, Recharts, Cytoscape.js via `react-cytoscapejs`, Framer Motion |
| Backend | Python 3.11+, FastAPI, Uvicorn, Pydantic, HTTPX, NetworkX, `packaging`, `defusedxml`, `tomllib` |
| Integrations | OSV.dev, GitHub REST API, CISA KEV, FIRST EPSS, Anthropic Claude (optional, `claude-opus-5-5`) |
| Tests | Pytest (all HTTP mocked), optional Playwright end-to-end tests |

There is no database, Redis or Docker. Scan results live in an in-memory store (see [Limitations](#known-limitations)).

## Prerequisites

- Python **3.11+** (uses `tomllib`; developed on 3.14)
- Node.js **20+** (developed on 24) and npm
- Internet access for live scans. The demo and the test suite run offline.

## Install and run

From the project root (`hyronai/`):

```bash
# 1. Backend
python -m venv .venv
.venv\Scripts\activate            # Windows
# source .venv/bin/activate       # macOS / Linux
pip install -r backend/requirements.txt

# 2. Frontend
cd frontend
npm install
cd ..
```

Run the backend and frontend in two terminals:

```bash
# Terminal 1 - API on http://localhost:8000
cd backend
uvicorn main:app --reload --port 8000
```

```bash
# Terminal 2 - app on http://localhost:5173
cd frontend
npm run dev
```

Open **http://localhost:5173**. The Vite dev server proxies `/api`, `/health` and `/docs` to the backend.

- Swagger UI: **http://localhost:8000/docs** (also linked in the app's profile menu)
- ReDoc: http://localhost:8000/redoc
- Production build: `cd frontend && npm run build` (outputs `frontend/dist/`)

## Configuration

Copy `.env.example` to `backend/.env` and fill in only what you need. **Everything is optional.** Without any keys, the demo, uploads, public GitHub repositories, website inspection and deterministic explanations all work.

| Variable | Purpose |
|---|---|
| `GITHUB_TOKEN` | Fine-grained, **read-only** token (`Contents: read`, `Metadata: read`). Enables private repositories the token can read and raises the GitHub rate limit. Users never enter passwords or tokens in the UI. |
| `ANTHROPIC_API_KEY` | Enables AI-written explanations in the Copilot |
| `HYRON_AI_MODEL` | Override the model (default `claude-opus-5-5`) |
| `HYRON_AI_ALLOW_PRIVATE_DATA` | `1` allows sending dependency metadata from **private** repositories to the AI service (default: never) |
| `HYRON_CORS_ORIGINS` | Allowed browser origins (default: localhost:5173) |
| `HYRON_SCAN_RATE_LIMIT` / `HYRON_SCAN_RATE_WINDOW` | Scan requests per client per window (default 30 per 600 s) |
| `HYRON_AI_RATE_LIMIT` / `HYRON_AI_RATE_WINDOW` | AI Copilot calls per client per window (default 20 per 600 s); template explanations are not limited |

Secrets are read only by the backend. They never appear in API responses (`/api/meta` reports only whether each integration is configured), in the frontend, or in browser storage.

## Testing

```bash
# from the project root, venv active
python -m pytest tests -q
```

**163 tests**, all offline with HTTP mocked, cover:

- **Parsing:** manifest parsing, including malformed, unsafe, oversized and non-UTF-8 input, and XXE / entity expansion.
- **Lockfiles:** npm v1/v2/v3 resolution, including nested `node_modules`, cycles, missing entries and manifest pairing; `poetry.lock` with and without `pyproject.toml`; Maven `dependency:tree`.
- **Versions:** version ordering for npm, PyPI and Maven; OSV range evaluation; constraint checks.
- **Advisories:** CVSS v3 calculation; OSV response parsing and normalisation; package and version matching.
- **Failure handling:** OSV outage, 429 rate limits, malformed responses, KEV outage, caching.
- **Graph:** traversal, direct vs transitive impact, runtime context, inferred links.
- **Scoring and planning:** HYRON Risk Score, including fallbacks and provisional flags; patch-plan ordering, commands and checklist.
- **GitHub:** URL validation, manifest discovery, commit pinning, 404/rate-limit errors.
- **Website inspection:** SSRF blocking (private, loopback and metadata IPs, IPv4-mapped IPv6, DNS to private ranges, redirects to private addresses), technology detection, potential-vs-confirmed labelling.
- **API behaviour:** workspace isolation, history, export, remediation status, re-scan verification, PR drafts, rate limiting.
- **Live failure:** if OSV is down, a live scan reports `verification_failed`, never success.
- **Demo:** the demo works without any credentials.

Optional browser end-to-end tests (Playwright). These need both servers running:

```bash
pip install playwright pytest
playwright install chromium        # or reuse an installed browser: set HYRON_E2E_CHANNEL=msedge / chrome
python -m pytest tests/e2e -q
```

## API

Interactive documentation is at `/docs`. All `/api` endpoints accept an optional `X-Workspace-Id` header (16–64 characters of `[A-Za-z0-9-]`); requests without one share the `default` workspace.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Service status |
| GET | `/api/meta` | Integration status (no secrets), limits, documented risk model |
| POST | `/api/demo` | Deterministic **simulated** scan of bundled sample data; no credentials needed |
| POST | `/api/scan` | Multipart upload (`files`, ≤10 files; manifests ≤1 MB, lockfiles ≤5 MB). Live scan |
| POST | `/api/scan/repository` | `{url, branch?}`. Fetches manifests and lockfiles at the branch head commit, then runs a live scan |
| POST | `/api/scan/website` | `{url, acknowledge_passive: true}`. Passive technology inspection |
| POST | `/api/repositories/validate` | `{url, branch?}`. Visibility, branches, commit and dependency files found, before scanning |
| GET | `/api/scans` | Scan history for the workspace |
| GET | `/api/graph/{scan_id}` | Cytoscape-ready nodes (type, ecosystem, version, status, depth, severity, risk) and edges (scope, inferred) plus a completeness flag |
| GET | `/api/reports/{scan_id}` | Full report: summary, findings with evidence, dependency paths, risk breakdown, remediation plan, data sources with timestamps, coverage gaps, limitations |
| GET | `/api/reports/{scan_id}/export` | JSON download |
| POST | `/api/reports/{scan_id}/explain` | `{finding_id?}`. AI Copilot or deterministic explanation |
| POST | `/api/reports/{scan_id}/remediation/status` | `{step_key, status, confirm?, note?}`. Status is `open`, `under_review` or `resolved_reported` (needs `confirm: true`) |
| POST | `/api/reports/{scan_id}/remediation/pr-draft` | `{step_key}`. Returns a PR title, branch and body; nothing is pushed |

Status codes:

| Code | Meaning |
|---|---|
| 201 | Scan created |
| 400 | Bad workspace header or too many files |
| 404 | Unknown scan, or repository not found / not accessible |
| 409 | Operation not applicable, e.g. a PR draft for a package with no fix |
| 413 | File too large |
| 415 | Unsupported file type |
| 422 | Invalid input, nothing parseable, blocked URL, or missing acknowledgement |
| 429 | HYRON rate limit or GitHub rate limit |
| 502 / 504 | Upstream error or timeout |

Unhandled errors return a generic 500 with no stack trace.

**Scan status.** Each report carries `completed`, `completed_with_gaps` (some packages could not be checked) or `verification_failed` (the live check failed for every package). The UI shows the last two prominently. An empty result from a failed check is never shown as "clean".

## How scanning works

1. **Discover.** Files are paired per directory. A lockfile supplies resolved versions and the transitive tree, and supersedes its manifest. `pyproject.toml` tells `poetry.lock` which packages are direct. A Maven tree report supersedes `pom.xml`. For a repository, HYRON pins the branch head commit and reads supported files only, skipping `node_modules/`, `vendor/`, build folders and oversized files.
2. **Versions.** Exact or resolved versions are scanned as-is. A declared range such as `^4.17.1` or `>=2.25` is scanned at its **lower bound** and flagged `(min)`. Anything unresolvable (`*`, git/URL dependencies, versions managed by a parent POM) becomes a **coverage gap**: shown as "not scanned", never as safe.
3. **Advisories.** OSV.dev is queried with `{ecosystem, name, version}` only. Each returned record must name the same ecosystem and package. HYRON then evaluates the record's `SEMVER`/`ECOSYSTEM` ranges locally:
   - `Confirmed advisory match`: the version is inside the affected range.
   - `OSV-reported match`: OSV matched the exact version, but the local check was inconclusive (for example, GIT-only ranges).
   - `Simulated`: demo data.
4. **Exploitation evidence.** CVE aliases are looked up in CISA KEV and FIRST EPSS. Responses are cached in memory (OSV 6 h, KEV/EPSS 12 h). If a refresh fails, stale cache is used and reported. If nothing is available, the value is **unknown**.
5. **Graph and blast radius.** NetworkX builds `project → package → package` edges, but **only edges stated by the input**. The one exception is a lockfile without its manifest, where root packages are attached to the project as **inferred** links, labelled and drawn dotted. Every project that reaches a vulnerable package is **potentially affected**. The shortest path is shown, and runtime context is computed per project: `production` if any all-production path exists, `development` if every path crosses a dev-only edge, otherwise `unknown`.
6. **Data sources.** Every report lists each source with its status (`ok`, `partial`, `stale`, `unavailable`, `synthetic`, `not_used`) and retrieval time.

**Website inspection** is separate. It makes one GET of the page, follows up to 3 validated redirects, and reads response headers and HTML. Results come in three labelled categories:

- **Technology detected:** observed in headers or markup.
- **Potential exposure:** a library version seen in a public asset URL or CDN path matches an OSV advisory. Unconfirmed.
- **Confirmed package vulnerability:** always empty. A URL cannot confirm installed packages.

## V-RPS (HYRON Risk Score)

A project-specific prioritisation heuristic, **not an industry standard**. All weights are defined in `backend/services/risk_engine.py`.

```
V-RPS = 0.35S + 0.30E + 0.20X + 0.15P
```

| Dimension | Evidence | When missing |
|---|---|---|
| Severity (S) | CVSS × 10 | Qualitative label → band midpoint. No severity → disclosed neutral 50; provisional |
| Exploit evidence (E) | 100 for CISA KEV, otherwise EPSS × 100 | Disclosed neutral 50; provisional and explicitly unknown |
| Exposure (X) | 100 production, 40 development-only | Disclosed neutral 50 for unknown context; provisional |
| Propagation (P) | 20 points per distinct affected project, capped at 100 | Zero when no scanned project is reachable |

Priority: **critical** ≥ 80, **high** ≥ 60, **medium** ≥ 35, otherwise **low**. All normalized factors and the substituted formula are displayed with each score. `missing_data` lists every fallback used.

**Urgent review.** Any finding listed in CISA KEV is flagged `urgent_review` whatever its V-RPS band. V-RPS prioritizes remediation; it does not predict exploitability.

Worked examples (asserted in tests):

| Case | Calculation | Score |
|---|---|---|
| KEV, production, 1 project | .35(98) + .30(100) + .20(100) + .15(20) | **87.3** |
| KEV, dev-only, 1 project | .35(98) + .30(100) + .20(40) + .15(20) | **75.3** |
| EPSS 0.35, production, 1 project | .35(53) + .30(35) + .20(100) + .15(20) | **52.0** |

Reachability in the graph is **not** treated as proof of exploitability.

## Remediation

Steps are ordered by HYRON Risk Score, then the number of production-context projects, then the number of affected projects. Each step includes:

- **Recommended version:** the highest per-advisory first-fixed version. It is re-checked against every matched advisory, giving a status of `fix_available`, `needs_review` or `no_fix_known`.
- **Per-project actions.** For direct dependencies, the step checks whether the declared constraint already allows the fix (if so, refreshing the lockfile is enough). For transitive dependencies, it names the parent to upgrade, or suggests an override, constraint or `dependencyManagement` entry.
- **Commands:** `npm install` / `npm pkg set overrides`, `pip` / `poetry`, `mvn versions:use-dep-version`, plus a verification command.
- **Checklist:** compatibility and regression items, with major-version and lower-bound warnings.
- **Status:** `open` → `under_review` → `resolved_reported`. A user-reported resolution needs an explicit confirmation and is labelled as user-reported. Only a **later scan of the same source** that no longer detects the package version sets `verified_by_rescan`. If a later scan still detects something marked resolved, the step shows `still_detected`.
- **PR draft:** title, branch name and Markdown body, with a compare link for repository scans. HYRON never pushes, merges or deploys.

## Security

**Implemented:**

- **Input validation.** Pydantic validates requests. Uploads are limited by type, size and count, and request bodies over the total upload limit are rejected before parsing. Inputs with no dependencies are rejected (422) rather than reported as clean, and a constraint without a version (e.g. `requests===`) is a coverage gap, never an OSV query. Malformed manifests are rejected, uploaded and repository files are never executed, and XML is parsed with `defusedxml`.
- **Upstream calls.** Every external call has a timeout. Upstream responses are validated as untrusted data.
- **SSRF.**
  - GitHub requests go only to the fixed host `api.github.com`, with strict URL and branch validation.
  - Website inspection allows only http/https on ports 80/443 and no embedded credentials. Every resolved IP must be globally routable, and redirects are re-validated hop by hop.
- **Secrets.** Kept in backend environment variables only. They are never returned, logged or stored in the browser. `.env` files are git-ignored.
- **Data isolation.** Scans are scoped per workspace using a random per-browser ID.
- **Error handling and CORS.** Errors are safe: no stack traces, credentials or paths. CORS is restricted to configured origins with a narrow header set. Basic security headers are set.
- **Rate limiting.** In-memory, per client, on scan and inspection endpoints, plus a separate limit on AI Copilot calls when an API key is configured.
- **Data minimisation.** OSV receives only package, ecosystem and version; EPSS receives only CVE IDs. The AI service receives only finding metadata, and never data from private repositories unless explicitly allowed.

**Not implemented** (needed before any real deployment):

- **Authentication and authorization.** The workspace ID provides isolation, not access control.
- **Persistent, encrypted storage.**
- **GitHub OAuth / GitHub App flow.** Private access uses one server-side token.
- **Distributed rate limiting.**
- **DNS-rebinding hardening.** Validated addresses are not pinned at connect time; add egress filtering at the network layer.
- **Audit logging.**
- **Formal security testing.** This prototype makes **no enterprise-grade security claims**.

## Known limitations

- **In-memory storage.** Results, history and remediation statuses are lost when the backend restarts. Each workspace keeps its last 50 scans.
- **Manifests without lockfiles.** These give direct dependencies only, scanned at range lower bounds. The graph is then marked **incomplete**, and the reasons are shown.
- **Unsupported formats.** Yarn/pnpm lockfiles, Pipfile.lock, Gradle and the Maven JSON/DOT report formats are not parsed. `poetry.lock` resolution assumes one version per package.
- **Severity coverage.** Only CVSS v3 vectors are computed. CVSS v4-only advisories fall back to their severity label, or to the provisional placeholder.
- **Version comparison.** The comparison logic for Maven and npm handles common formats. When a version can't be parsed, the local check returns "inconclusive" rather than guessing.
- **Upgrade guidance.** Suggested parent upgrades for transitive fixes are not checked against the registry. Compatibility is never verified.
- **Website inspection.** Only frontend assets are visible, versions inferred from file names can be wrong, and backend dependencies can't be seen.
- **GitHub limits.** Up to 30 dependency files per repository; anonymous access is limited to 60 requests/hour per IP.
- **AI Copilot.** Only tested with the deterministic fallback in this environment. The Claude path needs `ANTHROPIC_API_KEY`.

## Demo instructions

### Offline demo, about 5 minutes, no credentials

1. **Start.** Start both servers and open http://localhost:5173. The Overview shows an empty state.
2. **Run the demo.** Click **Run demo scan**. You land on the report. Point out the violet **Simulated demo data** banner: every package (`@hyron-demo/*`) and advisory (`HYRON-DEMO-*`) is fictional.
3. **Overview.** Cards show 3 vulnerable packages, 4 of 5 projects affected and 1 high priority. Severity and risk-trend charts are labelled **Demo Data**.
4. **Findings.** Expand `url-parser`. Severity (CVSS 9.8 from the vector), exploitability (simulated KEV) and exposure (3 production + 1 dev-only project) are shown separately, together with the formula `100 × (9.8/10) × (0.2 + 0.8 × 1.0) × 1 = 98.0`. `admin-portal` scores 39.2 because its path is dev-only. Click **Ask Copilot** for a structured explanation.
5. **Dependency Graph.** The vulnerable `url-parser` is pre-selected, and its blast radius is highlighted in red back to every project:
   - `payments-api` uses it directly,
   - `checkout-service` and `reporting-worker` get it through `http-client`,
   - `admin-portal` gets it through a dev-only test harness (dashed edge).

   `docs-site` stays green. `http-client@2.3.0` is *not* flagged, because its advisory only covers 1.x. Try the severity and status filters.
6. **Remediation Center.**
   - Step 1 upgrades `url-parser` to 1.4.5, with commands, an overrides command for transitive paths, and a checklist.
   - Step 3, `yaml-lite`, shows **No fix known**.
   - Click **Mark under review**, then **Prepare PR** to show the drafted PR.
7. **Report.** Click **Generate remediation report**, then **Print / Save PDF** and **Export JSON**.

### Live demo, internet required

1. **Upload.** In **New Scan → Upload**, drop `sample_data/package.json` + `package-lock.json` (paired automatically) and `sample_data/maven-dependency-tree.txt`. This yields real OSV advisories:
   - transitive `qs@6.7.0` and `follow-redirects`,
   - **Log4Shell** in `log4j-core 2.14.1`, which is in CISA KEV and scores 100.
2. **GitHub.** In **New Scan → GitHub**, validate `https://github.com/pallets/flask` (public, no token). It shows branches, the pinned commit and the files found. Scan it. Without lockfiles the report says **Completed with gaps** and the graph is marked incomplete. That's the honest result.
3. **Website.** In **New Scan → Website**, inspect a public site such as `https://jquery.com`. Results show **Technology detected** vs **Potential exposure**, and there are never confirmed vulnerabilities.
4. **Re-scan.** In **Repositories**, click **Re-scan**. If a package was upgraded in the meantime, the Remediation Center lists it under **Verified by re-scan**.

## Project structure

```
hyronai/
├── backend/
│   ├── main.py                       FastAPI app, CORS, security headers, /health, /api/meta
│   ├── requirements.txt
│   ├── routes/                       scan.py · repositories.py · graph.py · reports.py
│   ├── services/
│   │   ├── manifest_parser.py        manifests, lockfiles, trees, file pairing
│   │   ├── github_service.py         read-only GitHub access
│   │   ├── osv_service.py            OSV / KEV / EPSS clients + cache + data-source status
│   │   ├── vulnerability_scanner.py  matching, CVSS v3, normalisation, demo source
│   │   ├── versioning.py             version ordering, OSV ranges, constraint checks
│   │   ├── dependency_graph.py       NetworkX graph, blast radius, runtime context
│   │   ├── risk_engine.py            HYRON Risk Score (all weights)
│   │   ├── patch_planner.py          remediation plan, commands, checklists
│   │   ├── ai_explainer.py           AI Security Copilot + deterministic templates
│   │   ├── website_inspector.py      passive inspection + SSRF guards
│   │   ├── security.py               workspace scoping, rate limiting
│   │   └── pipeline.py               orchestration, in-memory store, remediation status
│   └── schemas/                      scan_result.py · vulnerability.py
├── frontend/
│   └── src/
│       ├── App.jsx · main.jsx · api.js · index.css
│       ├── context/AppContext.jsx    workspace, history, report cache, scan runner
│       ├── layout/Layout.jsx         sidebar, top bar, breadcrumbs, quick search
│       ├── pages/                    Overview, NewScan, Repositories, Findings, GraphPage,
│       │                             Remediation, History, Settings, Report, NotFound
│       └── components/               ui, SummaryCards, UploadPanel, RiskTable, DependencyGraph,
│                                     NodeDetails, PatchPlan, Copilot, Markdown, ScanBanner, WebsiteResult
├── sample_data/                      synthetic demo tree + real outdated manifests/lockfiles
├── tests/                            pytest suite (+ optional e2e/ Playwright tests)
├── .env.example
└── README.md
```
