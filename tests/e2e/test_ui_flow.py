"""Browser end-to-end check of the main demo workflow (optional).

Skipped unless Playwright is installed AND both servers are running:
    pip install playwright && playwright install chromium   (or set HYRON_E2E_CHANNEL=msedge / chrome)
    uvicorn main:app --port 8000      (backend/)
    npm run dev                       (frontend/)
    python -m pytest tests/e2e -q
"""

import os
import urllib.request

import pytest

sync_api = pytest.importorskip("playwright.sync_api")

BASE = os.getenv("HYRON_E2E_URL", "http://localhost:5173")


def _up(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return r.status == 200
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _up(f"{BASE}/health"), reason="frontend/backend not running")


@pytest.fixture
def page():
    with sync_api.sync_playwright() as p:
        channel = os.getenv("HYRON_E2E_CHANNEL")
        browser = p.chromium.launch(channel=channel) if channel else p.chromium.launch()
        pg = browser.new_page(viewport={"width": 1400, "height": 900})
        errors: list[str] = []
        pg.on("pageerror", lambda e: errors.append(str(e)))
        yield pg
        browser.close()
        assert not errors, errors


def test_demo_workflow(page):
    page.goto(f"{BASE}/scan/new?method=upload")
    page.get_by_role("button", name="Run demo scan").click()
    page.wait_for_selector("text=Security report")
    assert page.get_by_text("Simulated demo data.").first.is_visible()

    page.get_by_role("link", name="Vulnerability Findings").click()
    page.wait_for_selector("text=HYRON-DEMO-2026-0001")
    page.locator("tbody tr").first.click()
    page.wait_for_selector("text=V-RPS = 0.35(98)")

    page.get_by_role("link", name="Dependency Graph").click()
    page.wait_for_selector("canvas")
    page.wait_for_selector("text=Highest HYRON Risk")

    page.get_by_role("link", name="Remediation Center").click()
    page.wait_for_selector("text=Suggested commands")
    page.get_by_role("button", name="Mark under review").first.click()
    page.wait_for_selector("text=Under review")


def test_invalid_repository_url_shows_error(page):
    page.goto(f"{BASE}/scan/new?method=github")
    page.get_by_placeholder("https://github.com/owner/repository").fill("https://example.com/not/github")
    page.get_by_role("button", name="Validate access").click()
    # The error is shown inline under the URL field and the field is marked invalid.
    alert = page.locator("#repo-url-msg[role=alert]")
    alert.wait_for()
    assert "Enter a GitHub repository URL" in alert.inner_text()
    assert page.locator("#repo-url").get_attribute("aria-invalid") == "true"
