"""CRUD tests for User (SQLite, driven with contract-v2 tokens)."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from feathers_demo.main import app
from tests.tokens import auth


def _new_body() -> dict[str, object]:
    """A valid create body; unique columns get a fresh value per call."""
    seed = uuid.uuid4().hex[:8]
    return {
        "email": f"x{seed}",
        "full_name": "example",
        "role": "admin",
    }


def test_users_create_and_read() -> None:
    # ``with`` runs the lifespan, which creates the schema on SQLite.
    with TestClient(app) as client:
        created = client.request(
            "POST",
            "/users",
            json=_new_body(),
            headers=auth(),
        )
        assert created.status_code == 201, created.text
        item_id = created.json()["id"]

        fetched = client.request(
            "GET",
            f"/users/{item_id}",
            headers=auth(),
        )
        assert fetched.status_code == 200
        assert fetched.json()["id"] == item_id

        listed = client.request(
            "GET",
            "/users",
            headers=auth(),
        )
        assert listed.status_code == 200
        assert any(row["id"] == item_id for row in listed.json())

        item_id = uuid.uuid4()
        missing = client.request(
            "GET",
            f"/users/{item_id}",
            headers=auth(),
        )
        assert missing.status_code == 404


def test_users_soft_deleted_row_is_gone() -> None:
    """After a 204 the row answers 404 to every primary-key path.

    ``soft_delete: true`` keeps the row in the database (``deleted_at`` is set), so this
    is what proves every path filters it, not only the list.
    """
    with TestClient(app) as client:
        created = client.request(
            "POST",
            "/users",
            json=_new_body(),
            headers=auth(),
        )
        assert created.status_code == 201, created.text
        item_id = created.json()["id"]

        deleted = client.request(
            "DELETE",
            f"/users/{item_id}",
            headers=auth(),
        )
        assert deleted.status_code == 204, deleted.text

        gone = client.request(
            "GET",
            f"/users/{item_id}",
            headers=auth(),
        )
        assert gone.status_code == 404, gone.text

        edited = client.request(
            "PATCH",
            f"/users/{item_id}",
            json={},
            headers=auth(),
        )
        assert edited.status_code == 404, edited.text

        again = client.request(
            "DELETE",
            f"/users/{item_id}",
            headers=auth(),
        )
        assert again.status_code == 404, again.text

        listed = client.request(
            "GET",
            "/users",
            headers=auth(),
        )
        assert all(row["id"] != item_id for row in listed.json())


def test_users_enforce_declared_roles() -> None:
    """A viewer is authenticated but below every editor/admin route's role (403)."""
    item_id = uuid.uuid4()
    routes = [
        ("POST", "/users"),
        ("PATCH", f"/users/{item_id}"),
        ("DELETE", f"/users/{item_id}"),
    ]
    with TestClient(app) as client:
        for method, path in routes:
            response = client.request(
                method,
                path,
                json=_new_body(),
                headers=auth("viewer"),
            )
            assert response.status_code == 403, (method, path, response.text)
