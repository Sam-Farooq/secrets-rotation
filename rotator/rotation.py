"""Driving the machine against a store and a database.

The order is the whole argument:

    stage    the new password goes somewhere nobody reads yet
    set      it is installed on the user nobody is using
    verify   it is proved to work, as that user, before anything is published
    promote  consumers start resolving it, atomically
    quiesce  long enough for the last cached copy to expire
    revoke   and only now does the old password stop working

Nothing records where a run got to. The state of a half finished rotation is
read back from the store, which can only say whether a credential is staged,
and that is deliberately coarser than the machine: a recorded position is
written by the process that then died, and a position that disagrees with the
store is worse than no position at all.

What makes the coarse answer safe is that the steps before the promote are all
repeatable. Staging overwrites, ALTER ROLE is the same statement twice, and a
verify is a read. The promote is the exception, and it is not repeatable: it
refuses when nothing is staged rather than succeeding at nothing. A resumed run
never reaches it, because the thing it resumes from is a staged credential, and
after a promote there is not one.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import dataclass

from . import passwords
from .audit import Audit, NullAudit
from .config import Target
from .errors import RotatorError, StoreError
from .machine import Event, Machine, State, Step
from .ports import Clock, Credential, DatabaseAdmin, SecretStore


@dataclass(frozen=True)
class Outcome:
    target: str
    state: State
    history: tuple[Step, ...]
    rotated_to: str | None = None
    revoked: str | None = None
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.state is State.REVOKED

    @property
    def needs_a_human(self) -> bool:
        """True when the run stopped past the point of no return.

        A rolled back run is finished and safe. An abandoned one has published
        a new credential and left the old one alive, which is a least privilege
        finding rather than an outage, and nothing automatic will clear it.
        """
        return self.state is State.ABANDONED

    def summary(self) -> str:
        line = f"{self.target}: {self.state}"
        if self.rotated_to:
            line += f", now {self.rotated_to}"
        if self.revoked:
            line += f", revoked {self.revoked}"
        if self.reason:
            line += f" ({self.reason})"
        return line


class Rotation:
    def __init__(
        self,
        target: Target,
        store: SecretStore,
        admin: DatabaseAdmin,
        clock: Clock,
        audit: Audit | None = None,
        make_password: Callable[[int], str] = passwords.generate,
    ) -> None:
        self._target = target
        self._store = store
        self._admin = admin
        self._clock = clock
        self._audit = audit or NullAudit()
        self._make_password = make_password
        self._machine = Machine()

    @property
    def state(self) -> State:
        return self._machine.state

    def _fire(self, event: Event, detail: str = "") -> None:
        step = self._machine.fire(event, detail)
        self._audit.record(self._target.name, step, self._clock.now())

    def run(self) -> Outcome:
        target = self._target
        key = target.key
        rotated_to: str | None = None
        revoked: str | None = None
        reason = ""

        try:
            live = self._store.current(key)
            if live is None:
                raise StoreError(
                    f"{key} has no current credential. This tool rotates an existing "
                    f"secret and will not create the first one"
                )
            leftover = self._store.staged(key)
            if leftover is not None:
                raise StoreError(
                    f"{key} already has a staged credential for {leftover.username!r}. "
                    f"A previous run stopped before publishing it. Read "
                    f"docs/runbooks/stopped-before-promote.md, then "
                    f"`rotator discard {target.name}`"
                )

            incoming = Credential(
                username=target.other_user(live.username),
                password=self._make_password(target.password_length),
            )

            self._store.stage(key, incoming)
            self._fire(Event.CREATE, f"staged a password for {incoming.username}")

            self._admin.set_password(incoming.username, incoming.password)
            self._fire(Event.SET_PASSWORD, f"set on {incoming.username}")

            if not self._verified(incoming):
                # Nothing published, nothing revoked. The staged value goes,
                # and the inactive user keeps the password that just failed:
                # its old one is not recoverable and nobody is connecting as
                # it, so the next run overwrites it.
                detail = (
                    f"{incoming.username} did not authenticate after "
                    f"{target.verify_attempts} attempts, nothing was published"
                )
                self._discard(key)
                self._fire(Event.VERIFY_FAILED, detail)
                return self._outcome(reason=detail)
            self._fire(Event.VERIFY_OK, f"{incoming.username} authenticated")

            self._store.promote(key)
            rotated_to = incoming.username
            self._fire(Event.PROMOTE, f"consumers now resolve {incoming.username}")

            self._clock.sleep(target.quiesce_seconds)
            self._fire(Event.QUIESCE, f"waited {target.quiesce_seconds}s for caches to expire")

            self._admin.revoke(live.username)
            revoked = live.username
            self._fire(Event.REVOKE, f"{live.username} can no longer authenticate")

        except RotatorError as exc:
            reason = str(exc)
            self._bail(key, reason)
        except Exception as exc:  # an adapter raising something of its own
            reason = f"{type(exc).__name__}: {exc}"
            self._bail(key, reason)

        return self._outcome(rotated_to=rotated_to, revoked=revoked, reason=reason)

    def _verified(self, credential: Credential) -> bool:
        """Try the new credential, with a delay between attempts.

        The delay is not politeness. `ALTER ROLE` is immediate on the primary
        and a reader replica is not the primary, so a verify routed to a
        replica can fail once and pass on the next attempt.
        """
        for attempt in range(1, self._target.verify_attempts + 1):
            if self._admin.verify(credential):
                return True
            if attempt < self._target.verify_attempts:
                self._clock.sleep(self._target.verify_delay_seconds)
        return False

    def _discard(self, key: str) -> None:
        # Swallowed rather than raised. The caller is already reporting a
        # failure, and a second exception from the cleanup would replace the
        # message that says what went wrong first. What is left behind is a
        # staged credential, which the next plan reports as a blocker.
        with contextlib.suppress(RotatorError):
            self._store.discard_staged(key)

    def _bail(self, key: str, reason: str) -> None:
        if not self._machine.rolled_forward:
            self._discard(key)
        self._audit.record(
            self._target.name, self._machine.bail(reason), self._clock.now(), ok=False
        )

    def _outcome(self, **kwargs: object) -> Outcome:
        return Outcome(
            target=self._target.name,
            state=self._machine.state,
            history=tuple(self._machine.history),
            **kwargs,  # type: ignore[arg-type]
        )
