"""Platform token contract v2: the conformance cases a bastion-only service owes.

``Cn`` refers to the contract's conformance list (platform-contract-v2 §3). C5 needs a
frontend signing key, which a generated service does not trust, so it does not apply.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from feathers_demo.core import platform_token
from feathers_demo.core.config import Settings, settings
from feathers_demo.core.platform import install_platform_middleware
from feathers_demo.core.platform_token import (
    SERVICE_ID,
    Caller,
    Rejection,
    RequiredRole,
    fetch_key_document,
    install_platform_token,
    rate_limit_key,
    require_role,
    verify_token,
)
from feathers_demo.main import app
from tests.tokens import BASTION_KEY, claims, mint, public_key_b64, sign

NOW = 1_900_000_000
KEY = BASTION_KEY.public_key()
ROLES: tuple[RequiredRole, ...] = ("any", "viewer", "editor", "admin")
PLATFORM_ROUTES = (
    "/health",
    "/version",
    "/openapi.json",
    "/docs",
    "/redoc",
    "/metrics",
)


def _verify(*, drop: tuple[str, ...] = (), **overrides: object) -> Caller | Rejection:
    body = claims(**{"iat": NOW, "exp": NOW + 60, **overrides})
    for name in drop:
        del body[name]
    return verify_token(sign(body), KEY, now=NOW)


def _client() -> TestClient:
    """A minimal app behind the real middleware: one protected route per role."""
    test_app = FastAPI()
    install_platform_token(test_app)

    @test_app.get("/health")
    async def _health() -> dict[str, str]:
        return {"status": "ok"}

    @test_app.get("/protected")
    async def _protected() -> dict[str, str]:
        return {"ok": "yes"}

    for role in ROLES:

        @test_app.get(f"/role/{role}", dependencies=[Depends(require_role(role))])
        async def _guarded() -> dict[str, str]:
            return {"ok": "yes"}

    return TestClient(test_app)


def _token_header(token: str) -> dict[str, str]:
    return {"X-Platform-Token": token}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# ── verify_token: the pure core ─────────────────────────────────────────────


def test_c1_valid_bastion_token_is_accepted() -> None:
    result = _verify(sub="v_abc", role="editor")
    assert result == Caller(iss="bastion", sub="v_abc", role="editor")


def test_c2_audience_of_another_service_is_rejected() -> None:
    assert _verify(aud="magpie") == Rejection("aud")


def test_c3_missing_or_list_audience_is_rejected() -> None:
    assert _verify(drop=("aud",)) == Rejection("aud")
    assert _verify(aud=[SERVICE_ID]) == Rejection("aud")


def test_c4_only_bastions_key_and_issuer_are_trusted() -> None:
    stranger = Ed25519PrivateKey.generate()
    forged = sign(claims(iat=NOW, exp=NOW + 60), key=stranger)
    assert verify_token(forged, KEY, now=NOW) == Rejection("signature")
    assert _verify(iss="magpie-frontend") == Rejection("iss")


def test_c6_expiry_has_ten_seconds_of_leeway() -> None:
    assert isinstance(_verify(iat=NOW - 65, exp=NOW - 5), Caller)
    assert _verify(iat=NOW - 75, exp=NOW - 15) == Rejection("exp")


def test_c7_issued_at_has_ten_seconds_of_leeway() -> None:
    assert isinstance(_verify(iat=NOW + 5, exp=NOW + 65), Caller)
    assert _verify(iat=NOW + 15, exp=NOW + 75) == Rejection("iat")


def test_lifetime_is_at_most_three_hundred_seconds() -> None:
    assert isinstance(_verify(iat=NOW, exp=NOW + 300), Caller)
    assert _verify(iat=NOW, exp=NOW + 301) == Rejection("lifetime")
    assert _verify(iat=NOW, exp=NOW) == Rejection("lifetime")


def test_c8_unsigned_and_symmetric_algorithms_are_rejected() -> None:
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"iss": "bastion", "aud": SERVICE_ID}).encode())
    assert verify_token(f"{header}.{payload}.", KEY, now=NOW) == Rejection("alg")
    secret = "a-shared-secret-long-enough-for-hs256"
    hs256 = jwt.encode({"iss": "bastion", "aud": SERVICE_ID}, secret, algorithm="HS256")
    assert verify_token(hs256, KEY, now=NOW) == Rejection("alg")


def test_c9_tampered_payload_is_rejected() -> None:
    header, _, signature = mint(iat=NOW, exp=NOW + 60, role="viewer").split(".")
    raised = claims(iat=NOW, exp=NOW + 60, role="admin")
    forged = ".".join((header, _b64url(json.dumps(raised).encode()), signature))
    assert verify_token(forged, KEY, now=NOW) == Rejection("signature")


def test_claims_are_parsed_strictly() -> None:
    assert _verify(role="root") == Rejection("role")
    assert _verify(sub="") == Rejection("sub")
    assert _verify(exp=float(NOW + 60)) == Rejection("exp")
    assert _verify(iat=True) == Rejection("iat")
    assert _verify(drop=("sub",)) == Rejection("sub")


def test_garbage_and_non_object_payloads_are_malformed() -> None:
    assert verify_token("not-a-jwt", KEY, now=NOW) == Rejection("malformed")
    signed_list = jwt.PyJWS().encode(b"[1, 2]", BASTION_KEY, algorithm="EdDSA")
    assert verify_token(signed_list, KEY, now=NOW) == Rejection("malformed")


# ── the middleware: missing vs invalid, demo mode, fail closed ──────────────


def test_c1_valid_token_reaches_a_protected_route() -> None:
    response = _client().get("/protected", headers=_token_header(mint()))
    assert response.status_code == 200


def test_bearer_token_is_accepted_and_the_platform_header_wins() -> None:
    client = _client()
    bearer = {"Authorization": f"Bearer {mint()}"}
    assert client.get("/protected", headers=bearer).status_code == 200
    both = {**bearer, "X-Platform-Token": mint(aud="magpie")}
    assert client.get("/protected", headers=both).status_code == 401


def test_c10a_missing_token_is_refused() -> None:
    response = _client().get("/protected")
    assert response.status_code == 401
    assert response.json() == {"detail": "missing_platform_token"}
    blank = _client().get("/protected", headers={"X-Platform-Token": "  "})
    assert blank.json() == {"detail": "missing_platform_token"}


def test_c10b_demo_mode_lets_a_missing_token_through_with_a_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(settings, "demo_mode", True)
    with caplog.at_level(logging.WARNING, logger=platform_token.__name__):
        response = _client().get("/protected")
    assert response.status_code == 200
    assert any("DEMO_MODE" in record.getMessage() for record in caplog.records)


def test_c11_demo_mode_never_accepts_an_invalid_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "demo_mode", True)
    response = _client().get("/protected", headers=_token_header(mint(aud="magpie")))
    assert response.status_code == 401
    assert response.json() == {"detail": "invalid_platform_token"}


def test_c12_no_trusted_key_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "bastion_signing_key_public", "")
    client = _client()
    response = client.get("/protected", headers=_token_header(mint()))
    assert response.status_code == 503
    assert response.json() == {"detail": "platform_auth_unconfigured"}
    assert client.get("/health").status_code == 200


def test_c13_every_platform_route_answers_without_a_token_or_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "bastion_signing_key_public", "")
    client = TestClient(app)
    for path in PLATFORM_ROUTES:
        assert client.get(path).status_code == 200, path


def test_rejection_is_logged_by_check_never_by_token(caplog: pytest.LogCaptureFixture) -> None:
    token = mint(aud="magpie")
    with caplog.at_level(logging.WARNING, logger=platform_token.__name__):
        _client().get("/protected", headers=_token_header(token))
    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "'aud'" in messages
    assert token not in messages


def test_demo_mode_defaults_off() -> None:
    assert Settings.model_fields["demo_mode"].default is False


# ── key configuration ───────────────────────────────────────────────────────


def test_malformed_configured_key_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    ec_der = (
        generate_private_key(SECP256R1())
        .public_key()
        .public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    bad_keys = (
        "not base64!",
        base64.b64encode(b"not a key").decode(),
        base64.b64encode(ec_der).decode(),
    )
    for bad in bad_keys:
        platform_token.reset_key_cache()
        monkeypatch.setattr(settings, "bastion_signing_key_public", bad)
        response = _client().get("/protected", headers=_token_header(mint()))
        assert response.status_code == 503, bad


def test_key_is_fetched_from_the_url_once_and_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    async def _fake_fetch(url: str) -> str:
        calls.append(url)
        return public_key_b64(BASTION_KEY)

    monkeypatch.setattr(settings, "bastion_signing_key_public", "")
    monkeypatch.setattr(settings, "bastion_public_key_url", "https://bastion.test/api/public-key")
    monkeypatch.setattr(platform_token, "fetch_key_document", _fake_fetch)
    client = _client()
    assert client.get("/protected", headers=_token_header(mint())).status_code == 200
    assert client.get("/protected", headers=_token_header(mint())).status_code == 200
    assert calls == ["https://bastion.test/api/public-key"]


def test_unreachable_key_url_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _down(url: str) -> str:
        raise httpx.ConnectError("bastion is asleep")

    monkeypatch.setattr(settings, "bastion_signing_key_public", "")
    monkeypatch.setattr(settings, "bastion_public_key_url", "https://bastion.test/api/public-key")
    monkeypatch.setattr(platform_token, "fetch_key_document", _down)
    response = _client().get("/protected", headers=_token_header(mint()))
    assert response.status_code == 503


def test_key_document_is_parsed_with_a_schema() -> None:
    def _serve(body: bytes) -> httpx.MockTransport:
        return httpx.MockTransport(lambda request: httpx.Response(200, content=body))

    good = json.dumps({"kid": "k", "publicKey": "abc"}).encode()
    assert asyncio.run(fetch_key_document("https://b.test/k", transport=_serve(good))) == "abc"
    with pytest.raises(ValueError):
        asyncio.run(fetch_key_document("https://b.test/k", transport=_serve(b'{"kid": "k"}')))
    failing = httpx.MockTransport(lambda request: httpx.Response(500))
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(fetch_key_document("https://b.test/k", transport=failing))


# ── roles ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("role", "allowed"),
    [
        ("viewer", {"any", "viewer"}),
        ("frontend", {"any", "viewer"}),
        ("editor", {"any", "viewer", "editor"}),
        ("admin", {"any", "viewer", "editor", "admin"}),
    ],
)
def test_role_ranks_viewer_editor_admin(role: str, allowed: set[str]) -> None:
    client = _client()
    for required in ROLES:
        response = client.get(f"/role/{required}", headers=_token_header(mint(role=role)))
        assert response.status_code == (200 if required in allowed else 403), (role, required)


def test_anonymous_demo_caller_passes_role_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "demo_mode", True)
    assert _client().get("/role/admin").status_code == 200


def test_role_check_without_the_middleware_fails_closed() -> None:
    bare = FastAPI()

    @bare.get("/guarded", dependencies=[Depends(require_role("viewer"))])
    async def _guarded() -> dict[str, str]:
        return {"ok": "yes"}

    response = TestClient(bare).get("/guarded", headers=_token_header(mint()))
    assert response.status_code == 503


# ── rate limiting ───────────────────────────────────────────────────────────


def test_c14_rate_limit_key_is_issuer_and_subject() -> None:
    caller = Caller(iss="bastion", sub="v_abc", role="viewer")
    assert rate_limit_key(caller, forwarded_for="203.0.113.7", peer="10.0.0.1") == "bastion:v_abc"


def test_anonymous_rate_limit_key_is_the_leftmost_forwarded_address() -> None:
    key = rate_limit_key(None, forwarded_for="203.0.113.7, 10.0.0.2", peer="10.0.0.1")
    assert key == "203.0.113.7"
    assert rate_limit_key(None, forwarded_for="", peer="10.0.0.1") == "10.0.0.1"
    assert rate_limit_key(None, forwarded_for="", peer=None) == "unknown"


def test_each_caller_has_its_own_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "rate_limit_per_minute", 2)
    client = _client()
    first = _token_header(mint(sub="v_first"))
    for _ in range(2):
        assert client.get("/protected", headers=first).status_code == 200
    limited = client.get("/protected", headers=first)
    assert limited.status_code == 429
    assert limited.json() == {"detail": "rate_limited"}
    assert client.get("/protected", headers=_token_header(mint(sub="v_second"))).status_code == 200


# ── CORS ────────────────────────────────────────────────────────────────────


def test_cors_preflight_allows_the_platform_token_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "cors_origins", "https://app.example")
    test_app = FastAPI()
    install_platform_middleware(test_app, service_name="cors-check")
    client = TestClient(test_app)
    preflight = {
        "Origin": "https://app.example",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "x-platform-token",
    }
    allowed = client.options("/anything", headers=preflight)
    assert allowed.status_code == 200
    assert "x-platform-token" in allowed.headers["access-control-allow-headers"]
    refused = client.options(
        "/anything", headers={**preflight, "Access-Control-Request-Headers": "x-evil"}
    )
    assert refused.status_code == 400
