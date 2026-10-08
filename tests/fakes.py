"""Stand-ins for the four boundaries, hand written, nothing recorded.

None of this talks to anything. The Secrets Manager store is exercised against
moto; Vault, the database and the clock are replaced by the objects below.
"""

from __future__ import annotations

import datetime as dt

from rotator.errors import ProviderError
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
