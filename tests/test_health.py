"""Liveness and version, and the test database's isolation."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from feathers_demo.core.config import settings
from feathers_demo.main import app

client = TestClient(app)


def test_health_ok() -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["service"] == "feathers_demo"
    assert body["db"] == "ok"
    assert "commit_sha" in body


def test_version_ok() -> None:
    body = client.get("/version").json()
    assert body["service"] == "feathers_demo"
    assert "version" in body


def test_metrics_ok() -> None:
    resp = client.get("/metrics")
    assert resp.status_code == 200


def test_suite_database_is_isolated_from_the_working_directory() -> None:
    """With no DATABASE_URL the service would write ./feathers_demo.db and keep
    rows between runs; the test session must use its own temp database instead."""
    assert "feathers_demo.db" not in settings.database_url
    with TestClient(app) as isolated:
        assert isolated.get("/health").json()["db"] == "ok"
    assert not (Path.cwd() / "feathers_demo.db").exists()
