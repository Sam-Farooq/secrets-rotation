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

What goes over the wire. `ALTER ROLE ... WITH PASSWORD` sends whatever it is
given in the statement text, so a server running `log_statement = 'ddl'` or
`'all'` writes it to its own log, where it outlives the rotation. So the
plaintext is not what it is given: `rotator.scram` computes a SCRAM-SHA-256
verifier here and that is what the statement carries. The server never sees the
password, and the log line holds a string nobody can log in with.

The reason this was a known limitation for so long is the part that had to be
got right. A verifier only works if it matches how the server stores passwords,
and a mismatch leaves a role that cannot authenticate, which is the outage this
tool exists to prevent. So the settings are read from the server itself rather
than from config, on the same connection, immediately before the ALTER:

  password_encryption   refuse anything but scram-sha-256, because md5 and
                        plain take a different format entirely
  scram_iterations      a server may be moved off 4096, and a verifier built
                        with the wrong count will not authenticate

Both are read with `current_setting(..., true)`, the missing_ok form. The
obvious `SHOW scram_iterations` raises on any server below 16, and a raise
inside a transaction aborts it, so the ALTER that followed would fail with
"current transaction is aborted" and point at the wrong thing entirely.
"""

from __future__ import annotations

from typing import Any

from . import scram
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


# The only password_encryption this adapter can build a verifier for. md5 is a
# different format and is removed in Postgres 18; "plain" would put the
# password back in the statement, which is the whole thing being fixed.
SUPPORTED_ENCRYPTION = "scram-sha-256"


def server_scram_iterations(cursor: Any) -> int:
    """Read password_encryption and the iteration count off the live server.

    Takes a cursor rather than opening its own connection: these have to be the
    settings in force for the ALTER that follows, and a second connection could
    land on a different server behind a pooler, or on the same one after a
    reload.
    """
    cursor.execute("SELECT current_setting('password_encryption', true)")
    row = cursor.fetchone()
    encryption = str(row[0]).strip().lower() if row and row[0] is not None else ""
    if encryption != SUPPORTED_ENCRYPTION:
        raise ProviderError(
            f"server password_encryption is {encryption or 'unset'!r}, not "
            f"{SUPPORTED_ENCRYPTION!r}; refusing to set a verifier it will not accept"
        )

    cursor.execute("SELECT current_setting('scram_iterations', true)")
    row = cursor.fetchone()
    if not row or row[0] is None:
        # Below Postgres 16 the GUC does not exist and the count is fixed.
        return scram.DEFAULT_ITERATIONS
    try:
        iterations = int(row[0])
    except (TypeError, ValueError):
        raise ProviderError(
            f"server reported scram_iterations={row[0]!r}, which is not a number"
        ) from None
    if iterations < 1:
        raise ProviderError(f"server reported scram_iterations={iterations}, which cannot be used")
    return iterations


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
        role = self._role(username)
        try:
            with (
                psycopg.connect(self._admin_dsn, connect_timeout=self._connect_timeout) as conn,
                conn.cursor() as cursor,
            ):
                iterations = server_scram_iterations(cursor)
                statement = psycopg.sql.SQL("ALTER ROLE {} WITH PASSWORD {}").format(
                    psycopg.sql.Identifier(role),
                    psycopg.sql.Literal(scram.verifier(password, iterations=iterations)),
                )
                cursor.execute(statement)
        except ProviderError:
            # Already has a message written for whoever is reading the alert.
            raise
        except Exception as exc:
            # The statement carries a verifier rather than the password, so the
            # password cannot reach the message either way. psycopg still puts
            # the failing query in the exception it raises, and a verifier in
            # an alert is noise, so it is caught and replaced here.
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
