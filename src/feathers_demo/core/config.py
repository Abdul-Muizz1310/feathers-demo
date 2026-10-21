"""Environment-driven configuration."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Process settings, read from the environment (and a local ``.env``)."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    log_level: str = "info"
    port: int = 8000
    # Platform token contract v2: DEMO_MODE only lets a request with *no* token through,
    # as anonymous (logged). It never accepts an invalid token. Production keeps it off.
    demo_mode: bool = False
    # bastion's Ed25519 public key as base64 SPKI DER, or a URL serving {"publicKey": ...}.
    bastion_signing_key_public: str = ""
    bastion_public_key_url: str = ""
    # Requests per minute per caller (iss:sub), or per client address when anonymous.
    rate_limit_per_minute: int = Field(default=120, ge=1)
    cors_origins: str = ""
    # Empty → the app falls back to a local SQLite file (see core/db.py).
    database_url: str = ""


settings = Settings()
