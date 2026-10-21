"""Platform token verification — contract v2, bastion's key only.

Every route that is neither a platform route (``/health``, ``/version``, ``/metrics``,
the docs) nor a schema endpoint declared ``auth: none`` requires an EdDSA JWT minted by
bastion — in ``X-Platform-Token``, else ``Authorization: Bearer`` — whose ``aud`` is
this service's id. :func:`verify_token` holds the checks; a request that fails any of
them answers 401. With no trusted key configured every protected route answers 503
(fail closed). ``DEMO_MODE`` only lets a request with *no* token through, as
anonymous, with a WARNING; an invalid token is refused regardless.

Per-endpoint roles are enforced by :func:`require_role`, which the generated routers
attach from each endpoint's ``auth:`` declaration. Rate limits key on ``iss:sub`` for
an authenticated caller, else on the client address.
"""

from __future__ import annotations

import base64
import functools
import json
import logging
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Final, Literal

import httpx
import jwt
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from feathers_demo.core.config import settings
from feathers_demo.core.rate_limit import FixedWindowLimiter

logger = logging.getLogger(__name__)

#: This service's id: the only `aud` it accepts. A constant, never configuration.
SERVICE_ID: Final = "feathers-demo"
BASTION_ISSUER: Final = "bastion"
LEEWAY_S: Final = 10
MAX_LIFETIME_S: Final = 300
KEY_CACHE_TTL_S: Final = 3600.0

Role = Literal["viewer", "editor", "admin", "frontend"]
RequiredRole = Literal["any", "viewer", "editor", "admin"]

# viewer < editor < admin; a frontend ranks as a viewer; `any` is any authenticated role.
_ROLE_RANK: Final[dict[Role, int]] = {"viewer": 1, "frontend": 1, "editor": 2, "admin": 3}
_REQUIRED_RANK: Final[dict[RequiredRole, int]] = {"any": 1, "viewer": 1, "editor": 2, "admin": 3}

_PLATFORM_ROUTES: Final = frozenset(
    {"/health", "/version", "/metrics", "/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}
)

# Schema endpoints declared `auth: none`: public by design (method, mounted path).
_PUBLIC_ENDPOINTS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = ()

_Handler = Callable[[Request], Awaitable[Response]]
_UNSET: Final = object()


@dataclass(frozen=True, slots=True)
class Caller:
    """An authenticated caller."""

    iss: str
    sub: str
    role: Role


@dataclass(frozen=True, slots=True)
class Rejection:
    """Why a token was refused: the name of the first check it failed."""

    check: str


@dataclass(frozen=True, slots=True)
class Refusal:
    """The response a request that cannot be authenticated gets."""

    status_code: int
    detail: str


class _BastionClaims(BaseModel):
    """The claims a bastion token must carry, parsed strictly (no coercion)."""

    model_config = ConfigDict(strict=True, frozen=True, extra="ignore")

    iss: str
    aud: str
    sub: str = Field(min_length=1)
    role: Role
    exp: int
    iat: int


class _PublicKeyDocument(BaseModel):
    """bastion's public-key endpoint response (only the field used here)."""

    model_config = ConfigDict(extra="ignore")

    public_key: str = Field(alias="publicKey", min_length=1)


def verify_token(token: str, key: Ed25519PublicKey, *, now: int) -> Caller | Rejection:
    """Verify a compact JWS against bastion's key and contract v2's claim rules."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        return Rejection("malformed")
    if header.get("alg") != "EdDSA":
        return Rejection("alg")
    try:
        payload = jwt.PyJWS().decode(token, key, algorithms=["EdDSA"])
    except jwt.InvalidSignatureError:
        return Rejection("signature")
    except jwt.PyJWTError:
        return Rejection("malformed")
    try:
        raw = json.loads(payload)
    except ValueError:
        return Rejection("malformed")
    if not isinstance(raw, dict):
        return Rejection("malformed")
    try:
        claims = _BastionClaims.model_validate(raw)
    except ValidationError as exc:
        return Rejection(str(exc.errors()[0]["loc"][0]))
    if claims.iss != BASTION_ISSUER:
        return Rejection("iss")
    if claims.aud != SERVICE_ID:
        return Rejection("aud")
    if claims.exp + LEEWAY_S <= now:
        return Rejection("exp")
    if claims.iat - LEEWAY_S > now:
        return Rejection("iat")
    if not 0 < claims.exp - claims.iat <= MAX_LIFETIME_S:
        return Rejection("lifetime")
    return Caller(iss=claims.iss, sub=claims.sub, role=claims.role)


@functools.lru_cache(maxsize=4)
def parse_public_key(b64_der: str) -> Ed25519PublicKey | None:
    """Parse base64 SPKI DER into an Ed25519 key; None (logged) when it is not one."""
    try:
        key = load_der_public_key(base64.b64decode(b64_der, validate=True))
    except (ValueError, UnsupportedAlgorithm):
        logger.error("bastion public key is not base64 SPKI DER")
        return None
    if not isinstance(key, Ed25519PublicKey):
        logger.error("bastion public key is not an Ed25519 key")
        return None
    return key


async def fetch_key_document(
    url: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> str:
    """GET bastion's public-key document and return its ``publicKey`` field."""
    async with httpx.AsyncClient(timeout=5.0, transport=transport) as client:
        response = await client.get(url)
        response.raise_for_status()
    return _PublicKeyDocument.model_validate_json(response.content).public_key


# (url, fetched_at_monotonic, key) — only for the BASTION_PUBLIC_KEY_URL path.
_fetched: tuple[str, float, Ed25519PublicKey] | None = None


def reset_key_cache() -> None:
    """Forget the fetched and parsed keys (test seam)."""
    global _fetched
    _fetched = None
    parse_public_key.cache_clear()


async def resolve_bastion_key() -> Ed25519PublicKey | None:
    """bastion's verification key: the env value, else the URL's (cached for an hour)."""
    global _fetched
    raw = settings.bastion_signing_key_public.strip()
    if raw:
        return parse_public_key(raw)
    url = settings.bastion_public_key_url.strip()
    if not url:
        return None
    now = time.monotonic()
    if _fetched is not None and _fetched[0] == url and now - _fetched[1] < KEY_CACHE_TTL_S:
        return _fetched[2]
    try:
        document = await fetch_key_document(url)
    except (httpx.HTTPError, ValidationError) as exc:
        logger.warning("could not fetch bastion public key: %s", type(exc).__name__)
        return None
    key = parse_public_key(document)
    if key is not None:
        _fetched = (url, now, key)
    return key


def extract_token(request: Request) -> str | None:
    """The token from ``X-Platform-Token``, else ``Authorization: Bearer``; blank is absent."""
    header = request.headers.get("x-platform-token", "").strip()
    if header:
        return header
    scheme, _, credentials = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() == "bearer" and credentials.strip():
        return credentials.strip()
    return None


def is_platform_route(path: str) -> bool:
    """Liveness, version, metrics and docs: never authenticated, never rate limited."""
    return path in _PLATFORM_ROUTES


def is_public_endpoint(method: str, path: str) -> bool:
    """A schema endpoint declared ``auth: none``."""
    return any(m == method and p.match(path) is not None for m, p in _PUBLIC_ENDPOINTS)


def rate_limit_key(caller: Caller | None, *, forwarded_for: str, peer: str | None) -> str:
    """``iss:sub`` for an authenticated caller, else the leftmost forwarded address."""
    if caller is not None:
        return f"{caller.iss}:{caller.sub}"
    client = forwarded_for.split(",")[0].strip()
    return client or peer or "unknown"


async def authenticate(request: Request) -> Caller | Refusal | None:
    """The request's caller; None is an anonymous DEMO_MODE request."""
    key = await resolve_bastion_key()
    if key is None:
        logger.error("no bastion public key configured: refusing %s", request.url.path)
        return Refusal(503, "platform_auth_unconfigured")
    token = extract_token(request)
    if token is None:
        if not settings.demo_mode:
            return Refusal(401, "missing_platform_token")
        logger.warning(
            "DEMO_MODE: %s %s proceeds without a platform token",
            request.method,
            request.url.path,
        )
        return None
    result = verify_token(token, key, now=int(time.time()))
    if isinstance(result, Rejection):
        logger.warning(
            "platform token rejected on %s: failed check %r",
            request.url.path,
            result.check,
        )
        return Refusal(401, "invalid_platform_token")
    return result


def install_platform_token(app: FastAPI) -> None:
    """Authenticate every protected request and rate-limit every schema route."""
    limiter = FixedWindowLimiter(limit=settings.rate_limit_per_minute, window_s=60.0)
    if settings.demo_mode:
        logger.warning("DEMO_MODE is on: requests without a platform token proceed")

    @app.middleware("http")
    async def _platform_token_middleware(request: Request, call_next: _Handler) -> Response:
        if is_platform_route(request.url.path):
            return await call_next(request)
        caller: Caller | None = None
        if not is_public_endpoint(request.method, request.url.path):
            outcome = await authenticate(request)
            if isinstance(outcome, Refusal):
                return JSONResponse({"detail": outcome.detail}, status_code=outcome.status_code)
            caller = outcome
            request.state.platform_caller = caller
        key = rate_limit_key(
            caller,
            forwarded_for=request.headers.get("x-forwarded-for", ""),
            peer=request.client.host if request.client is not None else None,
        )
        if not limiter.allow(key):
            return JSONResponse({"detail": "rate_limited"}, status_code=429)
        return await call_next(request)


def current_caller(request: Request) -> Caller | None:
    """The caller the middleware authenticated; None is anonymous under DEMO_MODE.

    Any other state means the middleware never authenticated this request, so the
    dependency fails closed rather than guessing.
    """
    caller: object = getattr(request.state, "platform_caller", _UNSET)
    if caller is None or isinstance(caller, Caller):
        return caller
    raise HTTPException(status_code=503, detail="platform_auth_unconfigured")


def require_role(required: RequiredRole) -> Callable[[Request], Awaitable[None]]:
    """A FastAPI dependency enforcing an endpoint's declared ``auth:`` role (403)."""

    async def _dependency(request: Request) -> None:
        caller = current_caller(request)
        if caller is None:
            return
        if _ROLE_RANK[caller.role] < _REQUIRED_RANK[required]:
            raise HTTPException(status_code=403, detail="insufficient_role")

    return _dependency
