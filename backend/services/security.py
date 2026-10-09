"""Request-level safeguards: workspace scoping and rate limiting.

Workspace scoping: every request may carry X-Workspace-Id (the frontend
generates a random 32-hex ID per browser). Scans are stored and looked up
per workspace, so one browser cannot list or open another's results without
its ID. This is isolation by unguessable identifier, NOT authentication.

Rate limiting: a small in-memory sliding window per client address for
expensive endpoints (scans, repository and website inspection).
"""

from __future__ import annotations

import os
import re
import time
from collections import defaultdict, deque

from fastapi import Header, HTTPException, Request, status

_WORKSPACE_RE = re.compile(r"^[A-Za-z0-9-]{16,64}$")
DEFAULT_WORKSPACE = "default"


def workspace_id(x_workspace_id: str | None = Header(default=None)) -> str:
    if x_workspace_id is None:
        return DEFAULT_WORKSPACE
    if not _WORKSPACE_RE.match(x_workspace_id):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid X-Workspace-Id header")
    return x_workspace_id


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit, self.window = limit, window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> None:
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            retry = int(self.window - (now - hits[0])) + 1
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                f"Too many scan requests - try again in {retry} s",
                headers={"Retry-After": str(retry)},
            )
        hits.append(now)

    def reset(self) -> None:
        self._hits.clear()


SCAN_LIMITER = RateLimiter(
    limit=int(os.getenv("HYRON_SCAN_RATE_LIMIT", "30")),
    window_seconds=float(os.getenv("HYRON_SCAN_RATE_WINDOW", "600")),
)


def scan_rate_limit(request: Request) -> None:
    SCAN_LIMITER.check(request.client.host if request.client else "unknown")


# Separate budget for calls that reach the paid AI service, so the Copilot cannot be used
# to run up API costs. Deterministic explanations are free and are not limited.
AI_LIMITER = RateLimiter(
    limit=int(os.getenv("HYRON_AI_RATE_LIMIT", "20")),
    window_seconds=float(os.getenv("HYRON_AI_RATE_WINDOW", "600")),
)


def ai_rate_limit(request: Request) -> None:
    AI_LIMITER.check(request.client.host if request.client else "unknown")
