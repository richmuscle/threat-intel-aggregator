"""
API auth-gate tests.

Covers the four paths through `require_api_key`:

  1. `TIA_API_KEY` unset → dev mode, all requests pass (and a warning is
     emitted at import — we don't re-assert that here, just the behaviour).
  2. `TIA_API_KEY` set + no header → 401.
  3. `TIA_API_KEY` set + wrong header → 401 (and the compare is
     constant-time via `secrets.compare_digest`).
  4. `TIA_API_KEY` set + correct header → 200 (or 500 if DB not ready —
     either way, the auth gate passed).

Also verifies CORS is pinned to `TIA_CORS_ORIGINS` and `/api/v1/health`
stays unauthenticated regardless of gate state.
"""

from __future__ import annotations

import importlib
import os
import sys

import pytest
from fastapi.testclient import TestClient


def _reload_app_with_env(**env: str) -> TestClient:
    """Re-import the FastAPI app with a fresh env so `TIA_API_KEY` takes effect.

    `require_api_key` captures `TIA_API_KEY` at module import, so each test
    needs a fresh module — `sys.modules.pop` + `import_module` gives us a
    brand-new module instance that re-reads the env at import time.
    """
    for k in ("TIA_API_KEY", "TIA_CORS_ORIGINS"):
        os.environ.pop(k, None)
    os.environ.update(env)
    sys.modules.pop("src.api.app", None)
    module = importlib.import_module("src.api.app")
    # TestClient context-manager fires lifespan so the SQLite tables exist.
    return TestClient(module.app)


@pytest.fixture(autouse=True)
def _isolate_tia_api_key(monkeypatch):
    """Ensure each test starts from a clean slate (no key set)."""
    monkeypatch.delenv("TIA_API_KEY", raising=False)
    monkeypatch.delenv("TIA_CORS_ORIGINS", raising=False)
    yield


class TestAuthGate:
    def test_dev_mode_allows_unauthenticated(self) -> None:
        """When `TIA_API_KEY` is unset, the gate is a no-op."""
        with _reload_app_with_env() as client:
            resp = client.get("/api/v1/reports")
            # Gate passed → 200 (empty list) from the handler.
            assert resp.status_code == 200

    def test_401_without_header(self) -> None:
        with _reload_app_with_env(TIA_API_KEY="test-secret") as client:
            resp = client.get("/api/v1/reports")
            assert resp.status_code == 401
            assert "X-API-Key" in resp.json()["detail"]

    def test_401_with_wrong_key(self) -> None:
        with _reload_app_with_env(TIA_API_KEY="test-secret") as client:
            resp = client.get(
                "/api/v1/reports",
                headers={"X-API-Key": "wrong"},
            )
            assert resp.status_code == 401

    def test_200_with_correct_key(self) -> None:
        with _reload_app_with_env(TIA_API_KEY="test-secret") as client:
            resp = client.get(
                "/api/v1/reports",
                headers={"X-API-Key": "test-secret"},
            )
            assert resp.status_code == 200

    def test_health_unauthenticated_even_with_key_required(self) -> None:
        """Liveness must work without credentials for k8s probes."""
        with _reload_app_with_env(TIA_API_KEY="test-secret") as client:
            resp = client.get("/api/v1/health")
            assert resp.status_code == 200
            body = resp.json()
            assert set(body["components"]) >= {"sqlite", "anthropic_key", "api_auth"}
            assert body["components"]["api_auth"] == "enabled"

    def test_health_reports_dev_mode(self) -> None:
        with _reload_app_with_env() as client:
            body = client.get("/api/v1/health").json()
            assert body["components"]["api_auth"] == "dev-mode"


class TestCORSPinning:
    def test_wildcard_origin_stripped(self) -> None:
        """`*` in `TIA_CORS_ORIGINS` is filtered out defensively."""
        with _reload_app_with_env(TIA_CORS_ORIGINS="*,https://valid.example"):
            from src.api.app import CORS_ORIGINS

            assert "*" not in CORS_ORIGINS
            assert "https://valid.example" in CORS_ORIGINS

    def test_default_is_localhost_only(self) -> None:
        with _reload_app_with_env():
            from src.api.app import CORS_ORIGINS

            assert all("localhost" in o for o in CORS_ORIGINS)
