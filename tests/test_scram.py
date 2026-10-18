"""The verifier, checked against a vector this repo did not invent.

An implementation of RFC 5802 tested only against itself proves that two
calls agree, not that either is right, and a wrong verifier does not fail
loudly: it sets a role nobody can log in as. So the anchor here is the
SCRAM-SHA-256 exchange published in RFC 7677 §3, whose client proof and server
signature were computed by its authors.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re

import pytest

from rotator import scram

# RFC 7677 §3, verbatim.
RFC_PASSWORD = "pencil"
RFC_SALT = base64.b64decode("W22ZaJ0SNY7soEsUEjb6gQ==")
RFC_ITERATIONS = 4096
RFC_CLIENT_FIRST_BARE = "n=user,r=rOprNGfwEbeRWgbNEkqO"
RFC_SERVER_FIRST = (
    "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
)
RFC_CLIENT_FINAL_NO_PROOF = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
RFC_CLIENT_PROOF = "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
RFC_SERVER_SIGNATURE = "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="

AUTH_MESSAGE = ",".join(
    [RFC_CLIENT_FIRST_BARE, RFC_SERVER_FIRST, RFC_CLIENT_FINAL_NO_PROOF]
).encode("ascii")


def test_rfc7677_client_proof():
    """ClientProof = ClientKey XOR HMAC(StoredKey, AuthMessage)."""
    client_key, stored_key, _ = scram.derive(RFC_PASSWORD, RFC_SALT, RFC_ITERATIONS)
    signature = hmac.new(stored_key, AUTH_MESSAGE, hashlib.sha256).digest()
    proof = bytes(a ^ b for a, b in zip(client_key, signature, strict=True))
    assert base64.b64encode(proof).decode() == RFC_CLIENT_PROOF


def test_rfc7677_server_signature():
    """ServerSignature = HMAC(ServerKey, AuthMessage)."""
    _, _, server_key = scram.derive(RFC_PASSWORD, RFC_SALT, RFC_ITERATIONS)
    signature = hmac.new(server_key, AUTH_MESSAGE, hashlib.sha256).digest()
    assert base64.b64encode(signature).decode() == RFC_SERVER_SIGNATURE


def test_stored_key_is_the_hash_of_the_client_key():
    client_key, stored_key, _ = scram.derive("hunter2hunter2hunter2hun", b"\x01" * 16, 4096)
    assert stored_key == hashlib.sha256(client_key).digest()


def test_verifier_has_the_shape_postgres_parses():
    v = scram.verifier(RFC_PASSWORD, iterations=RFC_ITERATIONS, salt=RFC_SALT)
    match = re.fullmatch(r"SCRAM-SHA-256\$(\d+):([^$]+)\$([^:]+):(.+)", v)
    assert match, v
    iterations, salt_b64, stored_b64, server_b64 = match.groups()
    assert int(iterations) == RFC_ITERATIONS
    assert base64.b64decode(salt_b64) == RFC_SALT
    _, stored_key, server_key = scram.derive(RFC_PASSWORD, RFC_SALT, RFC_ITERATIONS)
    assert base64.b64decode(stored_b64) == stored_key
    assert base64.b64decode(server_b64) == server_key


def test_the_plaintext_is_nowhere_in_the_verifier():
    v = scram.verifier("correcthorsebatterystaple", iterations=4096)
    assert "correcthorsebatterystaple" not in v


def test_a_fresh_salt_every_call():
    """One offline attack should not cover two rotations."""
    a = scram.verifier("hunter2hunter2hunter2hun")
    b = scram.verifier("hunter2hunter2hunter2hun")
    assert a != b


def test_same_salt_and_iterations_is_deterministic():
    salt = b"\x02" * 16
    assert scram.verifier("pencil", iterations=4096, salt=salt) == scram.verifier(
        "pencil", iterations=4096, salt=salt
    )


def test_the_iteration_count_changes_the_keys():
    salt = b"\x03" * 16
    assert scram.derive("pencil", salt, 4096) != scram.derive("pencil", salt, 8192)


@pytest.mark.parametrize("password", ["pass wörd", "naïve-password-here-x", "pencil x"])
def test_non_ascii_refuses_rather_than_guessing_at_saslprep(password):
    with pytest.raises(ValueError, match="printable ASCII"):
        scram.verifier(password)


@pytest.mark.parametrize("password", ["has a space", "tab\there", "null\x00byte"])
def test_space_and_control_characters_refuse(password):
    with pytest.raises(ValueError, match="printable ASCII"):
        scram.verifier(password)


def test_every_password_this_tool_generates_is_acceptable():
    from rotator.passwords import generate

    for _ in range(50):
        scram.verifier(generate(48))


def test_iterations_below_one_refuses():
    with pytest.raises(ValueError, match="below 1"):
        scram.derive("pencil", RFC_SALT, 0)
