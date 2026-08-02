"""CRUD test for User (runs against a local SQLite database).

Note on Postgres coverage: ``asyncpg`` is a declared dependency and
``core/db.py`` has a Postgres-only pool_pre_ping/pool_recycle branch, but no
test here exercises that path — this suite only runs against SQLite. A
Testcontainers-backed Postgres integration test is deliberately NOT added in
this repo: this service is generated end-to-end by feathers-cli (see
``../feathers``), and every file here is a rendered copy of a
``.j2`` template with no Postgres/Testcontainers test template and no
``testcontainers`` dev dependency anywhere in the generator. Hand-adding an
integration tier only to this generated instance would make it diverge from
what the generator actually emits, which undermines the point of this repo
as a faithful proof artifact. The integration tier belongs upstream, as a
new template + dev dependency in the feathers generator itself, so every
generated service gets it consistently.
"""

from pathlib import Path

from fastapi.testclient import TestClient

from feathers_demo.main import app


def test_suite_does_not_leave_a_persistent_db_file_in_the_repo() -> None:
    """Regression: with no DATABASE_URL set, core/db.py falls back to a fixed
    relative-path file (``./feathers_demo.db``) that nothing deletes or
    resets between runs. A second consecutive ``pytest`` invocation then
    collides with rows the first run inserted (e.g. the hardcoded email
    below) and fails with a real ``sqlite3.IntegrityError``. Exercising the
    app must not leave that file behind in the repository's working
    directory.
    """
    stray_db = Path.cwd() / "feathers_demo.db"
    with TestClient(app) as client:
        resp = client.post(
            "/users",
            json={"email": "isolation@example.com", "full_name": "x", "role": "admin"},
        )
        assert resp.status_code == 201, resp.text
    assert not stray_db.exists(), (
        f"{stray_db} was created by the test run; the test database must be "
        "isolated to a temp path (see tests/conftest.py)"
    )


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
