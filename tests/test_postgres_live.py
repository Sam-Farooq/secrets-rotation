"""Facts about a real Postgres that no fake can produce.

The contract suite says the fake and the server agree. This file is the other
half: the things only a server knows, chiefly that the verifier this tool
derives is byte for byte the one Postgres derives for itself.

All of it is marked `live` and skips without ROTATOR_TEST_DSN.
"""

from __future__ import annotations

import base64

import live_postgres as live
import pytest

from rotator import scram
from rotator.database import PostgresAdmin, server_scram_iterations
from rotator.ports import Credential

pytestmark = pytest.mark.live

PASSWORD = "a-password-nobody-would-choose-9f3c"


@pytest.fixture
def roles():
    live.psycopg()
    made = live.Roles()
    made.create()
    yield made
    made.drop()


@pytest.fixture
def admin(roles):
    return PostgresAdmin(live.dsn(), live.verify_dsn_template())


def split_verifier(stored: str):
    """SCRAM-SHA-256$<iterations>:<salt>$<stored>:<server> into its parts."""
    algorithm, body = stored.split("$", 1)
    params, keys = body.split("$")
    iterations, salt_b64 = params.split(":")
    return algorithm, int(iterations), base64.b64decode(salt_b64), keys


def test_the_server_stores_what_this_tool_sent(admin, roles):
    admin.set_password(roles.app_a, PASSWORD)
    stored = live.stored_password(roles.app_a)
    assert stored is not None
    algorithm, iterations, salt, _ = split_verifier(stored)
    assert algorithm == "SCRAM-SHA-256"
    # Re-derive from the salt the server is holding. If this matches, the
    # server accepted the verifier verbatim rather than re-hashing anything.
    assert scram.verifier(PASSWORD, iterations=iterations, salt=salt) == stored


def test_our_derivation_is_the_one_postgres_does_for_itself(roles):
    """The cross-check the RFC vector cannot give.

    RFC 7677 proves this implements SCRAM. It does not prove it implements the
    same thing this particular server does, which is what actually decides
    whether a rotated role can log in. So: let Postgres hash a plaintext
    password itself, take the salt and iteration count it chose, and derive
    from the same inputs here. The two strings have to be identical.
    """
    pg = live.psycopg()
    import psycopg.sql

    # ALTER ROLE is a utility statement and takes no bound parameters: passing
    # one is a syntax error at the placeholder. Composed the same way the
    # adapter composes it, which is the only way to get a literal in there.
    statement = psycopg.sql.SQL("ALTER ROLE {} WITH PASSWORD {}").format(
        psycopg.sql.Identifier(roles.app_b), psycopg.sql.Literal(PASSWORD)
    )
    with pg.connect(live.dsn(), autocommit=True) as conn, conn.cursor() as cursor:
        cursor.execute(statement)
    theirs = live.stored_password(roles.app_b)
    _, iterations, salt, _ = split_verifier(theirs)
    assert scram.verifier(PASSWORD, iterations=iterations, salt=salt) == theirs


def test_the_iteration_count_read_is_the_one_the_server_uses(roles):
    pg = live.psycopg()
    with pg.connect(live.dsn()) as conn, conn.cursor() as cursor:
        reported = server_scram_iterations(cursor)

    pg_admin = PostgresAdmin(live.dsn(), live.verify_dsn_template())
    pg_admin.set_password(roles.app_a, PASSWORD)
    _, stored_iterations, _, _ = split_verifier(live.stored_password(roles.app_a))
    assert reported == stored_iterations


def test_the_alter_is_committed_and_not_left_in_a_transaction(admin, roles):
    """psycopg's connection context manager commits on a clean exit.

    Worth an assertion rather than an assumption: a rotation that reported
    success while the ALTER sat in an uncommitted transaction would strand a
    service, and every fake in the suite would still be green.
    """
    admin.set_password(roles.app_a, PASSWORD)
    # A connection opened afterwards sees it, which an uncommitted one would not.
    assert live.stored_password(roles.app_a) is not None
    assert live.stored_password(roles.app_a).startswith("SCRAM-SHA-256$")


def test_revoke_leaves_a_verifier_nobody_holds_the_password_for(admin, roles):
    admin.set_password(roles.app_b, PASSWORD)
    before = live.stored_password(roles.app_b)
    admin.revoke(roles.app_b)
    after = live.stored_password(roles.app_b)
    assert after != before
    assert after.startswith("SCRAM-SHA-256$")


def test_the_role_still_exists_after_revoke(admin, roles):
    admin.revoke(roles.app_b)
    pg = live.psycopg()
    with pg.connect(live.dsn()) as conn, conn.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (roles.app_b,))
        assert cursor.fetchone() is not None


def test_an_unknown_role_raises_providererror_not_something_psycopg_shaped(admin):
    from rotator.errors import ProviderError

    with pytest.raises(ProviderError) as caught:
        admin.set_password("rot_role_that_does_not_exist_4f81", PASSWORD)
    # The message must not carry the failing statement, which psycopg attaches.
    assert "PASSWORD" not in str(caught.value)


def test_a_wrong_password_is_refused_by_the_server(admin, roles):
    """Only meaningful where pg_hba actually checks one."""
    live.requires_password_auth()
    admin.set_password(roles.app_a, PASSWORD)
    assert admin.verify(Credential(roles.app_a, PASSWORD)) is True
    assert admin.verify(Credential(roles.app_a, "not-the-password-at-all-1234")) is False
