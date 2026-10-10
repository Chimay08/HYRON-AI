"""HYRON AI - software supply-chain security API.

Run from the backend/ directory:
    uvicorn main:app --reload --port 8000
Docs: http://localhost:8000/docs
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

ROOT = Path(__file__).resolve().parent
# Support both documented development launch styles:
#   cd backend; python -m uvicorn main:app
#   cd project; python -m uvicorn backend.main:app
# The route and service modules intentionally use backend-root imports.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

load_dotenv(ROOT / ".env")
load_dotenv(ROOT.parent / ".env")

from routes import graph, reports, repositories, scan  # noqa: E402  (after env is loaded)
from services import github_service, risk_engine  # noqa: E402
from services.ai_explainer import DEFAULT_MODEL, ai_configured  # noqa: E402
from services.manifest_parser import MAX_FILE_BYTES, MAX_LOCKFILE_BYTES, SUPPORTED_HELP  # noqa: E402
from services.security import SCAN_LIMITER  # noqa: E402

log = logging.getLogger("hyron")

app = FastAPI(
    title="HYRON AI",
    description=(
        "See the risk. Trace the impact. Fix it.\n\n"
        "Dependency vulnerability scanning (OSV.dev), exploitation evidence (CISA KEV, FIRST EPSS), "
        "blast-radius mapping, the HYRON Risk Score heuristic and remediation planning.\n\n"
        "Send `X-Workspace-Id` (16-64 chars of [A-Za-z0-9-]) to keep your scans separate; requests without it "
        "share the `default` workspace. Results are stored in memory only."
    ),
    version="0.2.0",
)

origins = [o.strip() for o in os.getenv("HYRON_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Workspace-Id"],
)


# Largest legitimate upload: every file at the lockfile limit, plus multipart overhead.
MAX_REQUEST_BYTES = scan.MAX_FILES * MAX_LOCKFILE_BYTES + 1_000_000


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    # Reject oversized bodies before the multipart parser spools them to disk.
    # Per-file limits are still enforced in the scan route.
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_REQUEST_BYTES:
        return JSONResponse(status_code=413, content={"detail": f"Request larger than {MAX_REQUEST_BYTES // 1_000_000} MB"})
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    # Log server-side; never leak stack traces, paths or secrets to clients.
    log.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


app.include_router(scan.router)
app.include_router(repositories.router)
app.include_router(graph.router)
app.include_router(reports.router)


@app.get("/health", tags=["meta"])
async def health():
    return {"status": "ok", "service": "hyron-ai", "version": app.version}


@app.get("/api/meta", tags=["meta"])
async def meta():
    """Integration status, limits and the documented risk model (no secrets are exposed)."""
    return {
        "version": app.version,
        "integrations": {
            "osv": {"enabled": True, "requires_credentials": False},
            "cisa_kev": {"enabled": True, "requires_credentials": False},
            "first_epss": {"enabled": True, "requires_credentials": False},
            "github": {"enabled": True, "token_configured": github_service.token_configured(),
                       "mode": "token" if github_service.token_configured() else "anonymous (public repositories only)"},
            "ai_copilot": {"enabled": ai_configured(), "provider": "Anthropic Claude",
                           "model": os.getenv("HYRON_AI_MODEL", DEFAULT_MODEL) if ai_configured() else None,
                           "private_data_allowed": os.getenv("HYRON_AI_ALLOW_PRIVATE_DATA", "0") == "1"},
        },
        "limits": {
            "max_files": scan.MAX_FILES, "manifest_bytes": MAX_FILE_BYTES, "lockfile_bytes": MAX_LOCKFILE_BYTES,
            "scan_rate_limit": f"{SCAN_LIMITER.limit} per {int(SCAN_LIMITER.window)} s per client",
        },
        "supported_files": SUPPORTED_HELP,
        "risk_model": risk_engine.describe(),
        "storage": "in-memory (cleared on restart)",
    }
