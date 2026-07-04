"""X-Platform-Token middleware — verifies bastion-minted Ed25519 platform JWTs.

In demo mode (the default for this deployment) the middleware accepts every
request and logs a one-time warning. When demo mode is off AND a bastion public
key is configured — either ``BASTION_SIGNING_KEY_PUBLIC`` (base64 DER) or fetched
once from ``BASTION_PUBLIC_KEY_URL`` and cached for an hour — it verifies the
EdDSA-signed ``X-Platform-Token`` on every non-exempt route and rejects invalid
or missing tokens with 401. The platform and docs endpoints are always exempt.

Enforcement is opt-in: with no key configured the middleware fails open, since
bastion is the only minter and frontends call this service directly in the
demo deployment. Token format is bastion's ``{sub, role, service, iat, exp}``
EdDSA JWT (see bastion ``src/lib/gateway/jwt.ts``).

Per-endpoint authorization is enforced by the :func:`require_role` dependency,
which the router wires onto each route from its schema ``auth:`` role. It shares
this module's trust model (demo mode and no-key both fail open) and, when
enforcing, decodes the token's ``role`` claim and rejects insufficient roles
with ``403``.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Awaitable, Callable

import anyio
import httpx
import jwt
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from feathers_demo.core.config import settings

logger = logging.getLogger(__name__)

_Handler = Callable[[Request], Awaitable[Response]]

_HEADER = "x-platform-token"
_EXEMPT_EXACT = frozenset({"/health", "/version", "/metrics", "/openapi.json"})
_EXEMPT_PREFIXES = ("/docs", "/redoc")
_PUBLIC_KEY_TTL_S = 3600.0

# Role hierarchy for per-endpoint `auth:` enforcement. A token satisfies a
# required role when its own role ranks at least as high.
_ROLE_RANK: dict[str, int] = {"viewer": 1, "editor": 2, "admin": 3}

# (fetched_at_monotonic, pem) — only used for the BASTION_PUBLIC_KEY_URL path.
_key_cache: tuple[float, str | None] = (0.0, None)


def reset_public_key_cache() -> None:
    """Clear the fetched-public-key cache (test seam)."""
    global _key_cache
    _key_cache = (0.0, None)


def _wrap_pem(b64_der: str) -> str:
    return f"-----BEGIN PUBLIC KEY-----\n{b64_der.strip()}\n-----END PUBLIC KEY-----\n"


def load_public_key_pem() -> str | None:
    """Resolve bastion's Ed25519 public key as PEM (env first, then cached URL)."""
    raw = os.environ.get("BASTION_SIGNING_KEY_PUBLIC")
    if raw:
        return _wrap_pem(raw)

    url = os.environ.get("BASTION_PUBLIC_KEY_URL")
    if not url:
        return None

    global _key_cache
    cached_at, cached = _key_cache
    now = time.monotonic()
    if cached is not None and (now - cached_at) < _PUBLIC_KEY_TTL_S:
        return cached
    try:
        resp = httpx.get(url, timeout=5.0)
        resp.raise_for_status()
        pem = _wrap_pem(str(resp.json()["publicKey"]))
    except Exception:  # pragma: no cover - network failure path
        logger.warning("could not fetch bastion public key from %s", url)
        return None
    _key_cache = (now, pem)
    return pem


def _is_exempt(path: str) -> bool:
    return path in _EXEMPT_EXACT or path.startswith(_EXEMPT_PREFIXES)


def _verify(token: str, pem: str) -> bool:
    try:
        jwt.decode(token, pem, algorithms=["EdDSA"])
    except Exception:
        return False
    return True


def install_platform_token(app: FastAPI, *, demo_mode: bool) -> None:
    """Attach the X-Platform-Token verification middleware to ``app``."""
    if demo_mode:
        logger.warning(
            "DEMO_MODE active: X-Platform-Token validation is bypassed; accepting all requests"
        )

    @app.middleware("http")
    async def _platform_token_middleware(request: Request, call_next: _Handler) -> Response:
        if demo_mode or _is_exempt(request.url.path):
            return await call_next(request)
        # Offload the (blocking) key resolution to a worker thread so a slow
        # bastion fetch never stalls the event loop / other in-flight requests.
        pem = await anyio.to_thread.run_sync(load_public_key_pem)
        if pem is None:
            # Enforcement is opt-in; with no key configured we fail open.
            return await call_next(request)
        token = request.headers.get(_HEADER)
        if not token or not _verify(token, pem):
            return JSONResponse({"error": "invalid platform token"}, status_code=401)
        return await call_next(request)


def require_role(required: str) -> Callable[[str | None], Awaitable[None]]:
    """Build a FastAPI dependency enforcing an endpoint's declared ``auth:`` role.

    Mirrors the middleware's trust model so the two never disagree:

    - In demo mode (the default), every request is accepted.
    - When enforcing but no bastion key is configured, enforcement is opt-in
      and the dependency fails open (consistent with the middleware).
    - Otherwise the ``X-Platform-Token`` must be present and validly signed;
      ``required="any"`` accepts any authenticated caller, while a concrete
      role (``viewer``/``editor``/``admin``) requires the token's ``role`` claim
      to rank at least as high — else ``403``.
    """

    async def _dependency(
        x_platform_token: str | None = Header(default=None, alias=_HEADER),
    ) -> None:
        if settings.demo_mode:
            return
        pem = await anyio.to_thread.run_sync(load_public_key_pem)
        if pem is None:
            return
        if not x_platform_token:
            raise HTTPException(status_code=401, detail="missing platform token")
        try:
            claims = jwt.decode(x_platform_token, pem, algorithms=["EdDSA"])
        except Exception as exc:
            raise HTTPException(status_code=401, detail="invalid platform token") from exc
        if required == "any":
            return
        role = str(claims.get("role", ""))
        if _ROLE_RANK.get(role, 0) < _ROLE_RANK.get(required, 0):
            raise HTTPException(status_code=403, detail="insufficient role")

    return _dependency
