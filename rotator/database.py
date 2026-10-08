"""The Postgres side of the two user pattern.

This adapter has never run against a live server. psycopg is an optional extra
and is imported inside the methods, so the package installs and the tests run
without it, and `rotator rotate` against a real database says which extra is
missing rather than failing on an import nobody reads.

What the three methods mean here:

  set_password   ALTER ROLE on the user nobody is currently using
  verify         open a connection as that user and run one statement
  revoke         ALTER ROLE the previous user to a password nobody knows

revoke does not DROP the role and does not REVOKE its grants. The role is used
again two rotations from now, and a role recreated every cycle is a set of
grants waiting to be forgotten.

Known limitation. `ALTER ROLE ... WITH PASSWORD` sends the password in the
statement text, so a server running `log_statement = 'ddl'` or `'all'` writes
it to its own log, where it outlives the rotation. The fix is to compute a
SCRAM-SHA-256 verifier on this side and send that instead. It is not here:
the verifier has to match the server's `password_encryption` setting, and a
mismatch produces a role that cannot log in, which is the failure this tool is
meant to prevent. Checking `log_statement` is on the runbook instead.
"""

from __future__ import annotations

from typing import Any

from .config import IDENTIFIER
from .errors import ProviderError
from .passwords import generate
from .ports import Credential


def _psycopg() -> Any:
    try:
        import psycopg
        import psycopg.sql
    except ModuleNotFoundError as exc:  # pragma: no cover - needs the extra absent
        raise ProviderError(
            "the postgres adapter needs psycopg: pip install 'secrets-rotation[postgres]'"
        ) from exc
    return psycopg


class PostgresAdmin:
    """Connects as an admin role to change other roles' passwords.

    The admin credential is a separate secret and is not rotated by this tool.
    Rotating the credential that performs rotations needs a second rotator, and
    the honest version of that is a human with a password manager once a year.
    """

    def __init__(self, admin_dsn: str, verify_dsn_template: str, connect_timeout: int = 5) -> None:
        self._admin_dsn = admin_dsn
        self._verify_dsn_template = verify_dsn_template
        self._connect_timeout = connect_timeout

    @staticmethod
    def _role(username: str) -> str:
        # psycopg.sql.Identifier quotes this properly anyway. The check is here
        # because a role name that does not match is a config mistake, and the
        # message from a quoted identifier Postgres has never heard of is
        # "role does not exist", which sends you looking in the wrong place.
        if not IDENTIFIER.match(username):
            raise ProviderError(f"{username!r} is not a role name this tool will act on")
        return username

    def set_password(self, username: str, password: str) -> None:
        psycopg = _psycopg()
        statement = psycopg.sql.SQL("ALTER ROLE {} WITH PASSWORD {}").format(
            psycopg.sql.Identifier(self._role(username)),
            psycopg.sql.Literal(password),
        )
        try:
            with (
                psycopg.connect(self._admin_dsn, connect_timeout=self._connect_timeout) as conn,
                conn.cursor() as cursor,
            ):
                cursor.execute(statement)
        except Exception as exc:
            # The statement carries the password as a literal, so it is never
            # in the message. psycopg puts the failing query in the exception
            # it raises, which is the reason to catch and replace it here.
            raise ProviderError(f"ALTER ROLE {username} failed: {type(exc).__name__}") from None

    def verify(self, credential: Credential) -> bool:
        psycopg = _psycopg()
        dsn = self._verify_dsn_template.format(
            username=credential.username, password=credential.password
        )
        try:
            with (
                psycopg.connect(dsn, connect_timeout=self._connect_timeout) as conn,
                conn.cursor() as cursor,
            ):
                cursor.execute("SELECT current_user")
                row = cursor.fetchone()
        except Exception:
            return False
        # Postgres folds an unquoted role name to lower case, and the whole
        # point of this call is to prove the connection is the user we think it
        # is rather than one a connection pooler substituted.
        return bool(row) and str(row[0]) == credential.username.lower()

    def revoke(self, username: str) -> None:
        self.set_password(self._role(username), generate(48))
