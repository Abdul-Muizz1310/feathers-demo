"""Environment-driven configuration."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    log_level: str = "info"
    port: int = 8000
    demo_mode: bool = True
    cors_origins: str = ""
    # Empty → the app falls back to a local SQLite file (see core/db.py).
    database_url: str = ""


settings = Settings()
