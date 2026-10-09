import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """No test may reach an AI service or depend on another test's state."""
    from services.osv_service import CACHE
    from services.pipeline import STORE
    from services.security import AI_LIMITER, SCAN_LIMITER

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    CACHE.clear()
    STORE.clear()
    SCAN_LIMITER.reset()
    AI_LIMITER.reset()
    yield
    CACHE.clear()
    STORE.clear()


@pytest.fixture
def no_network(monkeypatch):
    """Route every outbound httpx call made by the services to a handler that fails."""
    import httpx
    from services import osv_service

    def down(request):
        return httpx.Response(503)

    monkeypatch.setattr(
        osv_service, "new_client",
        lambda: httpx.AsyncClient(transport=httpx.MockTransport(down)),
    )
