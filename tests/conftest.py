"""Shared test fixtures.

Isolates the test database from the on-disk fallback file. With no
``DATABASE_URL`` set, ``core/db.py`` falls back to a fixed relative-path
SQLite file (``./feathers_demo.db``). Nothing resets or deletes that file
between runs, so a second consecutive ``pytest`` invocation collides with
rows the first run inserted and fails with a real ``sqlite3.IntegrityError``
(see ``tests/test_users.py::test_suite_does_not_leave_a_persistent_db_file_in_the_repo``).

Point every test session at a fresh SQLite file inside pytest's own
temp-file area instead, so each run gets a clean, isolated database with no
repo-directory side effects.

Provenance note: this file itself is a deliberate, minimal divergence from
what feathers-cli currently generates -- there is no ``conftest.py.j2`` in
the generator's ``templates/service/tests/`` directory, and the same
fixed-path fallback (``DEFAULT_DATABASE_URL`` in ``db.py.j2``) and the same
gap (no ``*.db`` line in ``.gitignore.j2``) exist in the generator's own
templates, so every service feathers-cli produces ships with this same
non-idempotent test suite. Unlike the Postgres/Testcontainers tier (see the
note in ``test_users.py``), this fix touches only test infrastructure -- no
new dependency, no change to generated ``src/`` behavior -- so it was worth
patching here rather than leaving the suite flaky. The proper long-term fix
is still upstream: add this fixture (or an equivalent tmp-path default) as a
``conftest.py.j2`` template, and add ``*.db`` to ``.gitignore.j2``, so future
generated services get isolated tests without a hand patch.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True, scope="session")
def _isolated_test_database(tmp_path_factory: pytest.TempPathFactory) -> None:
    from feathers_demo.core.config import settings

    db_path = tmp_path_factory.mktemp("db") / "test.db"
    settings.database_url = f"sqlite+aiosqlite:///{db_path}"
