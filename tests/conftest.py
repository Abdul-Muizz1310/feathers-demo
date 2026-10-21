"""Shared fixtures: an isolated database and contract-v2 platform settings.

* Database: with no ``DATABASE_URL`` the service falls back to a SQLite file in the
  working directory, which would keep rows between runs (a second run then collides
  on unique columns). Each session gets a fresh file under pytest's temp dir.
* Platform settings: every test starts from the contract's defaults
  (``DEMO_MODE=false``) with the test key trusted, so a local ``.env`` cannot change
  an outcome. A test that needs another state monkeypatches it.
"""

from __future__ import annotations

import pytest

from feathers_demo.core import platform_token
from feathers_demo.core.config import settings
from tests.tokens import BASTION_KEY, public_key_b64


@pytest.fixture(autouse=True, scope="session")
def _isolated_test_database(tmp_path_factory: pytest.TempPathFactory) -> None:
    db_path = tmp_path_factory.mktemp("db") / "test.db"
    settings.database_url = f"sqlite+aiosqlite:///{db_path}"


@pytest.fixture(autouse=True)
def _platform_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "demo_mode", False)
    monkeypatch.setattr(settings, "bastion_signing_key_public", public_key_b64(BASTION_KEY))
    monkeypatch.setattr(settings, "bastion_public_key_url", "")
    platform_token.reset_key_cache()
