from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi import Request
from fastapi.responses import Response

from secret_hunter.api import app, dashboard, detectors, security_headers


DASHBOARD = Path(__file__).parents[1] / "secret_hunter" / "dashboard"


def test_dashboard_assets_are_packaged_and_have_no_remote_dependencies() -> None:
    index = (DASHBOARD / "index.html").read_text(encoding="utf-8")
    css = (DASHBOARD / "dashboard.css").read_text(encoding="utf-8")
    javascript = (DASHBOARD / "dashboard.js").read_text(encoding="utf-8")

    assert '<link rel="stylesheet" href="/dashboard.css">' in index
    assert '<script src="/dashboard.js" defer></script>' in index
    assert "http://" not in index + css + javascript
    assert "https://" not in index + css
    assert "https://github.com/" in javascript
    assert "localStorage" not in javascript
    assert "document.cookie" not in javascript
    assert 'sessionStorage.getItem("sh_admin_token")' in javascript
    assert 'headers.set("Authorization", `Bearer ${state.token}`)' in javascript


def test_dashboard_exposes_all_operational_sections_and_actions() -> None:
    index = (DASHBOARD / "index.html").read_text(encoding="utf-8")
    javascript = (DASHBOARD / "dashboard.js").read_text(encoding="utf-8")

    for section in (
        "overview", "candidates", "findings", "notifications",
        "jobs", "pipeline", "runs", "detectors", "ai-providers",
    ):
        assert f'data-view-panel="{section}"' in index
    for endpoint in (
        "/stats", "/candidates?limit=500", "/findings?limit=500",
        "/notifications?limit=500", "/jobs?limit=500", "/runs?limit=500",
        "/detectors", "/events?limit=500", "/streams", "/jobs/repository",
    ):
        assert endpoint in javascript
    assert "/authorize-scan" in javascript
    assert "authorization_reference" in javascript
    assert "githubLocationUrl" in javascript
    assert "latest_commit_sha" in javascript
    assert "window.setInterval(refreshLive, 2000)" in javascript
    assert 'rel="noopener noreferrer"' in javascript
    assert 'window.location.hash.slice(1) || "overview"' in javascript
    assert 'data-action="provider-findings"' in javascript
    assert "renderAiProviders" in javascript


def test_ai_detector_metadata_supports_provider_dashboard() -> None:
    catalog = detectors("test-admin")
    ai = [item for item in catalog if item["category"] == "ai"]

    assert len(ai) >= 20
    assert all(item["detection_mode"] in {"prefix", "context"} for item in ai)
    assert all(item["search_signal"] for item in ai)
    assert all(item["docs_url"].startswith("https://") for item in ai)


def test_dashboard_mobile_breakpoint_releases_desktop_sidebar_column() -> None:
    css = (DASHBOARD / "dashboard.css").read_text(encoding="utf-8")

    mobile_rules = css.split("@media (max-width: 900px)", maxsplit=1)[1]
    mobile_rules = mobile_rules.split("@media (max-width: 620px)", maxsplit=1)[0]

    assert ".app-shell { display: block; }" in mobile_rules
    assert ".workspace { width: 100%; }" in mobile_rules


def test_dashboard_route_is_registered_and_points_to_local_file() -> None:
    paths = {route.path for route in app.routes}
    response = dashboard()

    assert {"/", "/dashboard.css", "/dashboard.js", "/events", "/streams"}.issubset(paths)
    assert Path(response.path).resolve() == (DASHBOARD / "index.html").resolve()
    assert response.media_type == "text/html"


def test_dashboard_security_headers_are_strict_and_not_cached() -> None:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8000),
        "root_path": "",
    }
    request = Request(scope)

    async def next_handler(_request: Request) -> Response:
        return Response("ok")

    response = asyncio.run(security_headers(request, next_handler))

    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert "object-src 'none'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
