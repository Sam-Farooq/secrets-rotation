"""Stand-ins for the four boundaries, hand written, nothing recorded.

None of this talks to anything. The Secrets Manager store is exercised against
moto; Vault, the database and the clock are replaced by the objects below.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from rotator.errors import ProviderError, StoreError
from rotator.ports import Credential

START = dt.datetime(2026, 3, 1, 3, 15, tzinfo=dt.UTC)


class FakeClock:
    """A clock that only moves when something sleeps, so a quiesce window of an
    hour costs nothing and the test can assert it was waited for."""

    def __init__(self, start: dt.datetime = START) -> None:
        self._at = start
        self.sleeps: list[float] = []

    def now(self) -> dt.datetime:
        return self._at

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self._at += dt.timedelta(seconds=seconds)


class FakeDatabase:
    """A password per role, and a verify that compares.

    `reject` makes a role's verify fail whatever the password is, which is how
    the failure path is driven. `transient` makes the first N verifies fail and
    the rest pass, for the replica lag case.
    """

    def __init__(
        self,
        passwords: dict[str, str],
        fail_set: tuple[str, ...] = (),
        fail_revoke: tuple[str, ...] = (),
        reject: tuple[str, ...] = (),
        transient: int = 0,
    ) -> None:
        self.passwords = dict(passwords)
        self.calls: list[tuple[str, str]] = []
        self._fail_set = frozenset(fail_set)
        self._fail_revoke = frozenset(fail_revoke)
        self._reject = frozenset(reject)
        self._transient = transient

    def set_password(self, username: str, password: str) -> None:
        self.calls.append(("set_password", username))
        if username in self._fail_set:
            raise ProviderError(f"ALTER ROLE {username} failed: PermissionDenied")
        self.passwords[username] = password

    def verify(self, credential: Credential) -> bool:
        self.calls.append(("verify", credential.username))
        if credential.username in self._reject:
            return False
        if self._transient > 0:
            self._transient -= 1
            return False
        return self.passwords.get(credential.username) == credential.password

    def revoke(self, username: str) -> None:
        self.calls.append(("revoke", username))
        if username in self._fail_revoke:
            raise ProviderError(f"ALTER ROLE {username} failed: ObjectInUse")
        self.passwords[username] = "scrambled"

    def works(self, username: str, password: str) -> bool:
        return self.passwords.get(username) == password

    def did(self, action: str) -> tuple[str, ...]:
        return tuple(username for name, username in self.calls if name == action)


class FakeVaultTransport:
    """KV v2, reduced to what the store uses: a document, a version, and
    check and set."""

    def __init__(self) -> None:
        self.documents: dict[str, dict[str, Any]] = {}
        self.versions: dict[str, int] = {}
        self.writes = 0
        # Set to simulate another writer landing between a read and the write
        # that follows it, which is the only thing check and set defends.
        self.race_next_read = False

    def seed(self, path: str, data: dict[str, Any]) -> None:
        self.documents[path] = dict(data)
        self.versions[path] = 1

    def request(self, method: str, path: str, body: dict[str, Any] | None) -> dict[str, Any]:
        key = path.replace("/data/", "/", 1)
        if method == "GET":
            if key not in self.documents:
                return {}
            response = {
                "data": {
                    "data": dict(self.documents[key]),
                    "metadata": {"version": self.versions[key]},
                }
            }
            if self.race_next_read:
                self.race_next_read = False
                self.versions[key] += 1
            return response
        if method == "POST":
            assert body is not None
            cas = body.get("options", {}).get("cas")
            if cas != self.versions.get(key, 0):
                raise StoreError(
                    f"vault POST {path} returned 400: check-and-set parameter did not "
                    f"match the current version"
                )
            self.documents[key] = dict(body["data"])
            self.versions[key] = cas + 1
            self.writes += 1
            return {"data": {"version": self.versions[key]}}
        raise AssertionError(f"unexpected method {method}")


class RecordingStore:
    """Wraps a store and records which methods were called, for the tests that
    care about what was not called."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.calls: list[str] = []

    def __getattr__(self, name: str) -> Any:
        attribute = getattr(self._inner, name)
        if not callable(attribute):
            return attribute

        def recorded(*args: Any, **kwargs: Any) -> Any:
            self.calls.append(name)
            return attribute(*args, **kwargs)

        return recorded
