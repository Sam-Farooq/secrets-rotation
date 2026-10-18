"""SCRAM-SHA-256 verifiers, so a password never travels in a statement.

`ALTER ROLE ... WITH PASSWORD '<plaintext>'` puts the password in the statement
text, and a server running `log_statement = 'ddl'` or `'all'` writes it to its
own log, where it outlives the rotation that retired it. Postgres also accepts a
pre-computed verifier in the same position and stores it verbatim, so computing
it here means the server never sees the plaintext and the log holds a string
that cannot be used to log in.

A verifier in a log is not nothing. It supports an offline guess at the
password, which is why the salt and the iteration count exist. It is not a
credential: authenticating needs ClientKey, and the verifier carries only
SHA-256(ClientKey), which does not invert. Against a 48 character password from
a 70 character alphabet the offline attack is not a threat anyone needs to
model.

The format is Postgres's own, from `src/backend/libpq/auth-scram.c`:

    SCRAM-SHA-256$<iterations>:<b64 salt>$<b64 StoredKey>:<b64 ServerKey>

and the derivation is RFC 5802 §3:

    SaltedPassword = PBKDF2-HMAC-SHA-256(password, salt, iterations, 32)
    ClientKey      = HMAC(SaltedPassword, "Client Key")
    StoredKey      = SHA-256(ClientKey)
    ServerKey      = HMAC(SaltedPassword, "Server Key")
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

# Postgres's default, and the value every server below 16 uses because the
# `scram_iterations` GUC did not exist before then. Read the server's own
# setting rather than assuming this one: a verifier built with the wrong
# iteration count produces a role that cannot log in.
DEFAULT_ITERATIONS = 4096

# RFC 5802 fixes 16 bytes for the SCRAM-SHA-256 salt and Postgres uses that.
SALT_BYTES = 16

_DIGEST = "sha256"
_KEY_LEN = 32


def _prepare(password: str) -> bytes:
    """SASLprep, for the subset of inputs where it is the identity function.

    Postgres runs SASLprep (RFC 4013) over a password before deriving a key
    from it, and so does libpq at login. For printable ASCII, SASLprep changes
    nothing, so no implementation of it is needed here. For anything else it
    changes something, and a verifier derived from an unprepared string would
    be one the server never reproduces: the role would be set and then fail to
    authenticate, which is precisely the outage this tool exists to prevent.

    So the unsupported case refuses rather than guesses. `generate()` draws
    from printable ASCII, so this never fires on a password this tool made.
    """
    if not password.isascii() or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in password):
        raise ValueError(
            "password is not printable ASCII, which this verifier cannot prepare correctly"
        )
    return password.encode("ascii")


def _hmac(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def derive(password: str, salt: bytes, iterations: int) -> tuple[bytes, bytes, bytes]:
    """The three keys of RFC 5802 §3, as (ClientKey, StoredKey, ServerKey).

    ClientKey is returned because proving this implementation correct means
    computing a client proof with it, which is what the RFC 7677 test vector
    checks. Nothing in the rotator itself needs it.
    """
    if iterations < 1:
        raise ValueError(f"iterations {iterations} is below 1")
    salted = hashlib.pbkdf2_hmac(_DIGEST, _prepare(password), salt, iterations, _KEY_LEN)
    client_key = _hmac(salted, b"Client Key")
    stored_key = hashlib.sha256(client_key).digest()
    server_key = _hmac(salted, b"Server Key")
    return client_key, stored_key, server_key


def verifier(
    password: str, *, iterations: int = DEFAULT_ITERATIONS, salt: bytes | None = None
) -> str:
    """The string to put where the plaintext password used to go.

    `salt` is a parameter so the test vectors can pin it. Leave it alone in
    production: a salt that repeats across rotations lets one offline attack
    cover both.
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    _, stored_key, server_key = derive(password, salt, iterations)
    b64 = lambda raw: base64.b64encode(raw).decode("ascii")  # noqa: E731
    return f"SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"
