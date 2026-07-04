"""Tests for the X-Platform-Token middleware (Ed25519 platform JWT verification)."""

from __future__ import annotations

import base64
import datetime as dt

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from feathers_demo.core import platform_token
from feathers_demo.core.platform_token import install_platform_token, require_role


def _make_app(*, demo_mode: bool) -> TestClient:
    app = FastAPI()
    install_platform_token(app, demo_mode=demo_mode)

    @app.get("/health", include_in_schema=False)
    async def _health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/protected")
    async def _protected() -> dict[str, str]:
        return {"ok": "yes"}

    return TestClient(app)


def _keypair() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, base64.b64encode(pub_der).decode()


def _token(priv_pem: str, *, expired: bool = False, role: str = "admin") -> str:
    now = dt.datetime.now(dt.UTC)
    exp = now - dt.timedelta(seconds=10) if expired else now + dt.timedelta(seconds=60)
    return jwt.encode(
        {"sub": "bastion", "role": role, "service": "feathers_demo", "exp": exp},
        priv_pem,
        algorithm="EdDSA",
    )


def _role_client(required: str) -> TestClient:
    """An app whose single route is guarded by ``require_role(required)``."""
    app = FastAPI()

    @app.get("/guarded", dependencies=[Depends(require_role(required))])
    async def _guarded() -> dict[str, str]:
        return {"ok": "yes"}

    return TestClient(app)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BASTION_SIGNING_KEY_PUBLIC", raising=False)
    monkeypatch.delenv("BASTION_PUBLIC_KEY_URL", raising=False)
    platform_token.reset_public_key_cache()


def test_demo_mode_accepts_without_token() -> None:
    client = _make_app(demo_mode=True)
    assert client.get("/protected").status_code == 200


def test_non_demo_without_key_fails_open() -> None:
    client = _make_app(demo_mode=False)
    assert client.get("/protected").status_code == 200


def test_non_demo_with_key_rejects_missing_token(monkeypatch: pytest.MonkeyPatch) -> None:
    _, pub_b64 = _keypair()
    monkeypatch.setenv("BASTION_SIGNING_KEY_PUBLIC", pub_b64)
    client = _make_app(demo_mode=False)
    assert client.get("/protected").status_code == 401
    # Platform endpoints stay exempt even when enforcement is on.
    assert client.get("/health").status_code == 200


def test_non_demo_with_key_accepts_valid_token(monkeypatch: pytest.MonkeyPatch) -> None:
    priv_pem, pub_b64 = _keypair()
    monkeypatch.setenv("BASTION_SIGNING_KEY_PUBLIC", pub_b64)
    client = _make_app(demo_mode=False)
    headers = {"X-Platform-Token": _token(priv_pem)}
    assert client.get("/protected", headers=headers).status_code == 200


def test_non_demo_with_key_rejects_tampered_token(monkeypatch: pytest.MonkeyPatch) -> None:
    priv_pem, pub_b64 = _keypair()
    monkeypatch.setenv("BASTION_SIGNING_KEY_PUBLIC", pub_b64)
    client = _make_app(demo_mode=False)
    headers = {"X-Platform-Token": f"{_token(priv_pem)}tampered"}
    assert client.get("/protected", headers=headers).status_code == 401


def test_non_demo_with_key_rejects_expired_token(monkeypatch: pytest.MonkeyPatch) -> None:
    priv_pem, pub_b64 = _keypair()
    monkeypatch.setenv("BASTION_SIGNING_KEY_PUBLIC", pub_b64)
    client = _make_app(demo_mode=False)
    headers = {"X-Platform-Token": _token(priv_pem, expired=True)}
    assert client.get("/protected", headers=headers).status_code == 401


def test_public_key_fetched_from_url_and_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    priv_pem, pub_b64 = _keypair()
    monkeypatch.setenv("BASTION_PUBLIC_KEY_URL", "https://bastion.example/api/public-key")

    calls = {"n": 0}

    class _Resp:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {"kid": "test", "algorithm": "EdDSA", "publicKey": pub_b64}

    def _fake_get(url: str, timeout: float) -> _Resp:
        calls["n"] += 1
        return _Resp()

    monkeypatch.setattr(platform_token.httpx, "get", _fake_get)
    client = _make_app(demo_mode=False)
    headers = {"X-Platform-Token": _token(priv_pem)}
    assert client.get("/protected", headers=headers).status_code == 200
    # Second request reuses the cached key (no second fetch).
    assert client.get("/protected", headers=headers).status_code == 200
    assert calls["n"] == 1


# ── require_role dependency (per-endpoint auth: role enforcement) ─────────────


def test_require_role_bypassed_in_demo_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform_token.settings, "demo_mode", True)
    client = _role_client("admin")
    # No token, demo mode → accepted.
    assert client.get("/guarded").status_code == 200


def test_require_role_fails_open_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform_token.settings, "demo_mode", False)
    client = _role_client("admin")
    # Enforcing but no key configured → opt-in, fail open.
    assert client.get("/guarded").status_code == 200


def test_require_role_rejects_missing_token(monkeypatch: pytest.MonkeyPatch) -> None:
    _, pub_b64 = _keypair()
    monkeypatch.setenv("BASTION_SIGNING_KEY_PUBLIC", pub_b64)
    monkeypatch.setattr(platform_token.settings, "demo_mode", False)
    client = _role_client("admin")
    assert client.get("/guarded").status_code == 401


def test_require_role_rejects_insufficient_role(monkeypatch: pytest.MonkeyPatch) -> None:
    priv_pem, pub_b64 = _keypair()
    monkeypatch.setenv("BASTION_SIGNING_KEY_PUBLIC", pub_b64)
    monkeypatch.setattr(platform_token.settings, "demo_mode", False)
    client = _role_client("admin")
    headers = {"X-Platform-Token": _token(priv_pem, role="viewer")}
    # A viewer token cannot satisfy an admin-only endpoint.
    assert client.get("/guarded", headers=headers).status_code == 403


def test_require_role_accepts_sufficient_role(monkeypatch: pytest.MonkeyPatch) -> None:
    priv_pem, pub_b64 = _keypair()
    monkeypatch.setenv("BASTION_SIGNING_KEY_PUBLIC", pub_b64)
    monkeypatch.setattr(platform_token.settings, "demo_mode", False)
    client = _role_client("editor")
    headers = {"X-Platform-Token": _token(priv_pem, role="admin")}
    # admin outranks editor → accepted.
    assert client.get("/guarded", headers=headers).status_code == 200


def test_require_role_any_accepts_any_valid_token(monkeypatch: pytest.MonkeyPatch) -> None:
    priv_pem, pub_b64 = _keypair()
    monkeypatch.setenv("BASTION_SIGNING_KEY_PUBLIC", pub_b64)
    monkeypatch.setattr(platform_token.settings, "demo_mode", False)
    client = _role_client("any")
    headers = {"X-Platform-Token": _token(priv_pem, role="viewer")}
    assert client.get("/guarded", headers=headers).status_code == 200
