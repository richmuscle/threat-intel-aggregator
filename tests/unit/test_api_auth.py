"""
API auth-gate tests.

Contract after session 8 hardening (Option A):

  • `TIA_API_KEY` unset and `TIA_AUTH_MODE` unset → `lifespan()` raises
    `RuntimeError` and the server refuses to start. Loopback is NOT exempt.
  • `TIA_AUTH_MODE=disabled` → explicit dev opt-out; all requests pass the
    gate. An ERROR log is emitted at startup.
  • `TIA_API_KEY` set + no header → 401.
  • `TIA_API_KEY` set + wrong header → 401 (constant-time via
    `secrets.compare_digest`).
  • `TIA_API_KEY` set + correct header → 200.

Also verifies CORS is pinned to `TIA_CORS_ORIGINS` and `/api/v1/health` is
reachable without credentials (for k8s probes) whenever the app can start.
"""

from __future__ import annotations

import importlib
import os
import sys

import pytest
from fastapi.testclient import TestClient


def _reload_app_with_env(**env: str) -> TestClient:
    """Re-import the FastAPI app with a fresh env so auth helpers see the right values.

    Since `require_api_key` now reads env at call time, a module reload is only
    needed for CORS_ORIGINS (read at import). We still reload to get a clean
    module state between tests.
    """
    for k in ("TIA_API_KEY", "TIA_CORS_ORIGINS", "TIA_AUTH_MODE", "TIA_API_HOST"):
        os.environ.pop(k, None)
    os.environ.update(env)
    sys.modules.pop("src.api.app", None)
    module = importlib.import_module("src.api.app")
    # TestClient context-manager fires lifespan so the SQLite tables exist.
    return TestClient(module.app)


@pytest.fixture(autouse=True)
def _isolate_tia_api_key(monkeypatch):
    """Ensure each test starts from a clean slate (no auth env vars set)."""
    monkeypatch.delenv("TIA_API_KEY", raising=False)
    monkeypatch.delenv("TIA_CORS_ORIGINS", raising=False)
    monkeypatch.delenv("TIA_AUTH_MODE", raising=False)
    monkeypatch.delenv("TIA_API_HOST", raising=False)
    yield


class TestAuthGate:
    def test_lifespan_refuses_to_start_when_unset_no_opt_out(self) -> None:
        """Unset key + no TIA_AUTH_MODE=disabled → lifespan raises, server won't start."""
        for k in ("TIA_API_KEY", "TIA_AUTH_MODE"):
            os.environ.pop(k, None)
        sys.modules.pop("src.api.app", None)
        module = importlib.import_module("src.api.app")
        with pytest.raises(RuntimeError, match="TIA_API_KEY must be set"):
            with TestClient(module.app):
                pass  # should not reach body — lifespan raises on context entry

    def test_disabled_mode_allows_unauthenticated(self) -> None:
        """TIA_AUTH_MODE=disabled bypasses the gate (explicit dev opt-out)."""
        with _reload_app_with_env(TIA_AUTH_MODE="disabled") as client:
            resp = client.get("/api/v1/reports")
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
        """With TIA_AUTH_MODE=disabled opt-out, health reports dev-mode."""
        with _reload_app_with_env(TIA_AUTH_MODE="disabled") as client:
            body = client.get("/api/v1/health").json()
            assert body["components"]["api_auth"] == "dev-mode"


class TestRequireApiKeyDirect:
    """Direct unit tests for require_api_key using call-time env helpers."""

    async def test_require_api_key_rejects_missing_header_when_key_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No header + TIA_API_KEY set → 401."""
        from fastapi import HTTPException

        from src.api.app import require_api_key

        monkeypatch.setenv("TIA_API_KEY", "secret")
        monkeypatch.delenv("TIA_AUTH_MODE", raising=False)
        with pytest.raises(HTTPException) as exc_info:
            await require_api_key(None)
        assert exc_info.value.status_code == 401

    async def test_require_api_key_rejects_bad_header_when_key_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Wrong header value + key set → 401."""
        from fastapi import HTTPException

        from src.api.app import require_api_key

        monkeypatch.setenv("TIA_API_KEY", "secret")
        monkeypatch.delenv("TIA_AUTH_MODE", raising=False)
        with pytest.raises(HTTPException) as exc_info:
            await require_api_key("wrong")
        assert exc_info.value.status_code == 401

    async def test_require_api_key_accepts_good_header(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Correct header value → no exception."""
        from src.api.app import require_api_key

        monkeypatch.setenv("TIA_API_KEY", "secret")
        monkeypatch.delenv("TIA_AUTH_MODE", raising=False)
        await require_api_key("secret")  # must not raise

    async def test_require_api_key_raises_503_when_unset_without_opt_out(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No key, no TIA_AUTH_MODE=disabled → 503 defence-in-depth."""
        from fastapi import HTTPException

        from src.api.app import require_api_key

        monkeypatch.delenv("TIA_API_KEY", raising=False)
        monkeypatch.delenv("TIA_AUTH_MODE", raising=False)
        with pytest.raises(HTTPException) as exc_info:
            await require_api_key(None)
        assert exc_info.value.status_code == 503

    async def test_require_api_key_bypasses_when_auth_mode_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """TIA_AUTH_MODE=disabled → passes regardless of key or header."""
        from src.api.app import require_api_key

        monkeypatch.delenv("TIA_API_KEY", raising=False)
        monkeypatch.setenv("TIA_AUTH_MODE", "disabled")
        await require_api_key(None)  # must not raise

    async def test_lifespan_raises_when_unset_without_opt_out(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No key + no TIA_AUTH_MODE=disabled → RuntimeError before DB init.

        Loopback is not exempt: the contract is the same on every host to
        avoid ``it worked in dev`` gaps.
        """
        from fastapi import FastAPI

        from src.api.app import lifespan

        monkeypatch.delenv("TIA_API_KEY", raising=False)
        monkeypatch.delenv("TIA_AUTH_MODE", raising=False)
        dummy_app = FastAPI()
        with pytest.raises(RuntimeError, match="TIA_API_KEY must be set"):
            async with lifespan(dummy_app):
                pass  # should not reach here


class TestCORSPinning:
    def test_wildcard_origin_stripped(self) -> None:
        """`*` in `TIA_CORS_ORIGINS` is filtered out defensively."""
        with _reload_app_with_env(
            TIA_CORS_ORIGINS="*,https://valid.example",
            TIA_AUTH_MODE="disabled",
        ):
            from src.api.app import CORS_ORIGINS

            assert "*" not in CORS_ORIGINS
            assert "https://valid.example" in CORS_ORIGINS

    def test_default_is_localhost_only(self) -> None:
        with _reload_app_with_env(TIA_AUTH_MODE="disabled"):
            from src.api.app import CORS_ORIGINS

            assert all("localhost" in o for o in CORS_ORIGINS)
