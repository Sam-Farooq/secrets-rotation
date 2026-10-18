"""What the Postgres adapter puts in the statement, and what it refuses.

The other half of keeping a password out of a log. `test_secrets_stay_out_of_
the_log.py` greps what this tool writes; these tests grep what it sends, which
is the half that ends up in somebody else's log file rather than ours.

psycopg is an optional extra and is not installed in CI, so the module is
replaced here with a stand-in that renders the composed statement to a string.
That is enough to answer the only question worth asking of it: is the password
in there.
"""

from __future__ import annotations

import pytest

from rotator import database, scram
from rotator.errors import ProviderError
from rotator.ports import Credential

PASSWORD = "a-password-nobody-would-choose-9f3c"


class FakeCursor:
    """Answers the two current_setting calls and records everything executed."""

    def __init__(self, encryption="scram-sha-256", iterations="4096", current_user=None):
        self._settings = {"password_encryption": encryption, "scram_iterations": iterations}
        self._current_user = current_user
        self._last = None
        self.executed: list[str] = []

    def execute(self, statement):
        text = str(statement)
        self.executed.append(text)
        for name, value in self._settings.items():
            if f"'{name}'" in text:
                self._last = (value,)
                return
        if "current_user" in text:
            self._last = (self._current_user,) if self._current_user else None
            return
        self._last = None

    def fetchone(self):
        return self._last

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def fake_psycopg(cursor):
    """The two pieces of psycopg this adapter touches: connect, and sql."""

    class SQL:
        def __init__(self, template):
            self._template = template

        def format(self, *parts):
            out = self._template
            for part in parts:
                out = out.replace("{}", str(part), 1)
            return out

    class Identifier:
        def __init__(self, name):
            self._name = name

        def __str__(self):
            return f'"{self._name}"'

    class Literal:
        def __init__(self, value):
            self._value = value

        def __str__(self):
            return "'" + str(self._value).replace("'", "''") + "'"

    class Module:
        sql = type("sql", (), {"SQL": SQL, "Identifier": Identifier, "Literal": Literal})

        @staticmethod
        def connect(dsn, connect_timeout=None):
            return FakeConnection(cursor)

    return Module


@pytest.fixture
def admin(monkeypatch):
    def build(encryption="scram-sha-256", iterations="4096", current_user=None):
        cursor = FakeCursor(encryption, iterations, current_user)
        monkeypatch.setattr(database, "_psycopg", lambda: fake_psycopg(cursor))
        admin = database.PostgresAdmin("postgresql://admin@localhost/db", "{username}:{password}")
        return admin, cursor

    return build


def test_the_alter_carries_a_verifier_and_not_the_password(admin):
    pg, cursor = admin()
    pg.set_password("orders_app_a", PASSWORD)
    alter = [s for s in cursor.executed if "ALTER ROLE" in s]
    assert len(alter) == 1
    assert PASSWORD not in alter[0]
    assert "SCRAM-SHA-256$4096:" in alter[0]


def test_nothing_the_adapter_sends_holds_the_password(admin):
    pg, cursor = admin()
    pg.set_password("orders_app_a", PASSWORD)
    assert PASSWORD not in " ".join(cursor.executed)


def test_the_verifier_sent_is_one_the_password_reproduces(admin):
    """A verifier that does not round-trip is a role nobody can log in as."""
    pg, cursor = admin()
    pg.set_password("orders_app_a", PASSWORD)
    sent = [s for s in cursor.executed if "ALTER ROLE" in s][0].split("'")[1]
    import base64

    _, body = sent.split("$", 1)
    params, keys = body.split("$")
    iterations, salt_b64 = params.split(":")
    rebuilt = scram.verifier(PASSWORD, iterations=int(iterations), salt=base64.b64decode(salt_b64))
    assert rebuilt == sent
    assert keys  # stored:server, both present


def test_the_servers_iteration_count_is_used_not_the_default(admin):
    pg, cursor = admin(iterations="15000")
    pg.set_password("orders_app_a", PASSWORD)
    alter = [s for s in cursor.executed if "ALTER ROLE" in s][0]
    assert "SCRAM-SHA-256$15000:" in alter


def test_a_server_below_16_has_no_guc_and_gets_the_fixed_count(admin):
    pg, cursor = admin(iterations=None)
    pg.set_password("orders_app_a", PASSWORD)
    alter = [s for s in cursor.executed if "ALTER ROLE" in s][0]
    assert f"SCRAM-SHA-256${scram.DEFAULT_ITERATIONS}:" in alter


def test_the_setting_is_read_with_the_missing_ok_form(admin):
    """`SHOW scram_iterations` raises below 16, and a raise aborts the transaction."""
    pg, cursor = admin()
    pg.set_password("orders_app_a", PASSWORD)
    reads = [s for s in cursor.executed if "current_setting" in s]
    assert len(reads) == 2
    assert all(", true)" in s for s in reads)
    assert not any(s.strip().upper().startswith("SHOW ") for s in cursor.executed)


@pytest.mark.parametrize("encryption", ["md5", "plain", None, ""])
def test_an_unsupported_encryption_refuses_before_altering_anything(admin, encryption):
    pg, cursor = admin(encryption=encryption)
    with pytest.raises(ProviderError, match="password_encryption"):
        pg.set_password("orders_app_a", PASSWORD)
    assert not any("ALTER ROLE" in s for s in cursor.executed)


def test_a_nonsense_iteration_count_refuses(admin):
    pg, cursor = admin(iterations="many")
    with pytest.raises(ProviderError, match="not a number"):
        pg.set_password("orders_app_a", PASSWORD)
    assert not any("ALTER ROLE" in s for s in cursor.executed)


def test_a_zero_iteration_count_refuses(admin):
    pg, cursor = admin(iterations="0")
    with pytest.raises(ProviderError, match="cannot be used"):
        pg.set_password("orders_app_a", PASSWORD)
    assert not any("ALTER ROLE" in s for s in cursor.executed)


def test_revoke_scrambles_through_the_same_path(admin):
    """The retired role's new password is random and also never sent in clear."""
    pg, cursor = admin()
    pg.revoke("orders_app_b")
    alter = [s for s in cursor.executed if "ALTER ROLE" in s]
    assert len(alter) == 1
    assert '"orders_app_b"' in alter[0]
    assert "SCRAM-SHA-256$" in alter[0]


def test_a_role_name_that_is_not_an_identifier_never_reaches_the_server(admin):
    pg, cursor = admin()
    with pytest.raises(ProviderError, match="role name"):
        pg.set_password("orders_app_a; DROP DATABASE orders", PASSWORD)
    assert cursor.executed == []


def test_verify_still_authenticates_with_the_plaintext(admin):
    """verify() is deliberately unchanged.

    Setting a password now sends a verifier; proving the credential works still
    means opening a connection as that user with the password itself. That is
    what makes sending a verifier safe to attempt: if the derivation were ever
    wrong, this step fails and the old credential is never revoked.
    """
    pg, cursor = admin(current_user="orders_app_a")
    assert pg.verify(Credential("orders_app_a", PASSWORD)) is True
    assert any("current_user" in s for s in cursor.executed)


def test_verify_fails_when_the_session_is_a_different_role(admin):
    pg, cursor = admin(current_user="someone_else")
    assert pg.verify(Credential("orders_app_a", PASSWORD)) is False
