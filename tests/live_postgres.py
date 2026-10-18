"""Wiring for the tests that need a real Postgres, and the trap in them.

`ROTATOR_TEST_DSN` points at a database where this suite may create and drop
roles. Unset, every live test skips, which is what keeps the default run
offline and Docker-free.

The trap is worth stating because it cost an afternoon. A server whose pg_hba
says `trust` accepts any password for any role, so "connect with the wrong
password" succeeds and a test asserting the rotation works passes without
anything having been checked. That is worse than no test: it is a green tick
over an unexercised path. `password_auth_enforced()` asks the server what it
would actually do, and the tests that depend on authentication skip with a
reason rather than pass vacuously.
"""

from __future__ import annotations

import os
import uuid

import pytest

DSN_ENV = "ROTATOR_TEST_DSN"


def dsn() -> str:
    value = os.environ.get(DSN_ENV)
    if not value:
        pytest.skip(f"{DSN_ENV} is not set, so there is no server to run against")
    return value


def psycopg():
    try:
        import psycopg
    except ModuleNotFoundError:  # pragma: no cover - the extra is absent
        pytest.skip("psycopg is not installed: pip install '.[postgres]'")
    return psycopg


def verify_dsn_template() -> str:
    """The admin DSN with the credential swapped in, for the verify step."""
    import urllib.parse as urlparse

    parts = urlparse.urlsplit(dsn())
    host = parts.hostname or "localhost"
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{{username}}:{{password}}@{host}{port}{parts.path}"


def password_auth_enforced() -> bool:
    """Does this server actually check a password on the connections we make?

    Read from `pg_hba_file_rules` rather than assumed. A `trust` line matching
    host connections means no password is ever checked, and every assertion
    about a wrong password being refused would hold for the wrong reason.
    """
    pg = psycopg()
    with pg.connect(dsn(), connect_timeout=5) as conn, conn.cursor() as cursor:
        cursor.execute(
            "SELECT auth_method FROM pg_hba_file_rules "
            "WHERE type = 'host' AND 'all' = ANY(database) AND error IS NULL "
            "ORDER BY line_number"
        )
        methods = [row[0] for row in cursor.fetchall()]
    return bool(methods) and methods[0] not in ("trust", "reject")


def requires_password_auth():
    if not password_auth_enforced():
        pytest.skip(
            "this server's pg_hba uses trust for host connections, so a wrong "
            "password would be accepted and this assertion would pass vacuously"
        )


class Roles:
    """Two login roles and one that cannot log in, dropped on the way out.

    Names carry a uuid because this may be pointed at a shared development
    server, and a fixed name would collide with whatever else is on it.
    """

    def __init__(self) -> None:
        suffix = uuid.uuid4().hex[:10]
        self.app_a = f"rot_a_{suffix}"
        self.app_b = f"rot_b_{suffix}"
        self.nologin = f"rot_n_{suffix}"

    @property
    def all(self) -> tuple[str, ...]:
        return (self.app_a, self.app_b, self.nologin)

    def create(self) -> None:
        pg = psycopg()
        with pg.connect(dsn(), autocommit=True) as conn, conn.cursor() as cursor:
            for name in (self.app_a, self.app_b):
                cursor.execute(f'CREATE ROLE "{name}" LOGIN')
            cursor.execute(f'CREATE ROLE "{self.nologin}" NOLOGIN')

    def drop(self) -> None:
        pg = psycopg()
        with pg.connect(dsn(), autocommit=True) as conn, conn.cursor() as cursor:
            for name in self.all:
                # Named one at a time on purpose. This may be a shared server,
                # and a pattern here could drop something that is not ours.
                cursor.execute(f'DROP ROLE IF EXISTS "{name}"')


def stored_password(role: str) -> str | None:
    pg = psycopg()
    with pg.connect(dsn(), connect_timeout=5) as conn, conn.cursor() as cursor:
        cursor.execute("SELECT rolpassword FROM pg_authid WHERE rolname = %s", (role,))
        row = cursor.fetchone()
    return row[0] if row else None
