"""The four boundaries this tool talks across, and the credential that moves
over them.

Everything that needs a network lives behind one of these. That is what makes
the test suite offline: Secrets Manager is the only one with a real
implementation under test, through moto, and it is the only one where the
request shape is subtle enough to be worth checking against a server at all.
"""

from __future__ import annotations

import datetime as dt
import time
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class Credential:
    """A username and password pair.

    The repr is redacted on purpose. A dataclass prints its fields, this object
    ends up in exception messages, log lines and pytest failure output, and a
    password in any of those outlives the rotation that was supposed to retire
    it.
    """

    username: str
    password: str

    def __repr__(self) -> str:
        return f"Credential(username={self.username!r}, password=<redacted>)"

    __str__ = __repr__


@runtime_checkable
class SecretStore(Protocol):
    """Where consumers read the credential from.

    Reads are `current`, `staged` and `current_age`. Writes are `stage`,
    `promote` and `discard_staged`. `rotator plan` is allowed to call only the
    first three, and tests/test_plan_is_read_only.py holds that line at the
    boto3 layer rather than trusting this comment.
    """

    def current(self, secret_id: str) -> Credential | None: ...

    def staged(self, secret_id: str) -> Credential | None: ...

    def current_age(self, secret_id: str, now: dt.datetime) -> dt.timedelta | None: ...

    def stage(self, secret_id: str, credential: Credential) -> str: ...

    def promote(self, secret_id: str) -> None: ...

    def discard_staged(self, secret_id: str) -> None: ...


@runtime_checkable
class DatabaseAdmin(Protocol):
    """The database, as far as a rotation needs it.

    `revoke` means the old password stops working. It does not mean the role is
    dropped or its grants removed: the two user pattern hands that same role the
    next rotation but one, and a role rebuilt from scratch each cycle is a set
    of grants waiting to be forgotten.
    """

    def set_password(self, username: str, password: str) -> None: ...

    def verify(self, credential: Credential) -> bool: ...

    def revoke(self, username: str) -> None: ...


@runtime_checkable
class Clock(Protocol):
    def now(self) -> dt.datetime: ...

    def sleep(self, seconds: float) -> None: ...


class SystemClock:
    def now(self) -> dt.datetime:
        return dt.datetime.now(dt.UTC)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)
