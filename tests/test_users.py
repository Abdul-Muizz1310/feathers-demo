"""CRUD test for User (runs against a local SQLite database)."""

from fastapi.testclient import TestClient

from feathers_demo.main import app


def test_users_create_and_read() -> None:
    # ``with`` runs the lifespan, which creates the schema on SQLite.
    with TestClient(app) as client:
        created = client.post(
            "/users",
            json={
                "email": "example",
                "full_name": "example",
                "role": 'admin',
            },
        )
        assert created.status_code == 201, created.text
        item_id = created.json()["id"]

        fetched = client.get(f"/users/{item_id}")
        assert fetched.status_code == 200
        assert fetched.json()["id"] == item_id

        listed = client.get("/users")
        assert listed.status_code == 200
        assert any(row["id"] == item_id for row in listed.json())
