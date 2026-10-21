"""A test stand-in for bastion's signing key, and a minter for platform tokens.

The service trusts exactly one issuer, bastion. Tests sign real EdDSA tokens with a
key pair made once per session; ``conftest.py`` points ``BASTION_SIGNING_KEY_PUBLIC``
at its public half. There is no test-mode bypass in the service itself.
"""

from __future__ import annotations

import base64
import time
import uuid
from collections.abc import Mapping

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from feathers_demo.core.platform_token import SERVICE_ID

BASTION_KEY = Ed25519PrivateKey.generate()


def public_key_b64(key: Ed25519PrivateKey) -> str:
    """A key's public half as base64 SPKI DER (the ``BASTION_SIGNING_KEY_PUBLIC`` format)."""
    der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode()


def claims(**overrides: object) -> dict[str, object]:
    """Contract-v2 claims for a bastion admin call, with ``overrides`` applied."""
    now = int(time.time())
    base: dict[str, object] = {
        "iss": "bastion",
        "aud": SERVICE_ID,
        "service": SERVICE_ID,
        "sub": f"v_{uuid.uuid4().hex[:10]}",
        "role": "admin",
        "cap": "test.call",
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
    }
    base.update(overrides)
    return base


def sign(payload: Mapping[str, object], *, key: Ed25519PrivateKey = BASTION_KEY) -> str:
    """Sign ``payload`` as an EdDSA compact JWS (bastion's format)."""
    return jwt.encode(dict(payload), key, algorithm="EdDSA", headers={"kid": "test-key"})


def mint(**overrides: object) -> str:
    """A signed bastion token: :func:`claims` with ``overrides``."""
    return sign(claims(**overrides))


def auth(role: str = "admin") -> dict[str, str]:
    """Request headers carrying a fresh token for ``role`` (a fresh ``sub`` each call)."""
    return {"X-Platform-Token": mint(role=role)}
