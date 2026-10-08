"""The two phase state machine.

A credential cannot be revoked until every consumer holds the new one, so a
rotation is not one action. It is a sequence with a point of no return in the
middle, and the only property worth protecting is this one: nothing is revoked
unless the new credential has been proved to work and then published.

The table below is the whole contract. It is data rather than a chain of ifs so
that the tests can walk it, which is how `PROMOTE` is held as the point of no
return: before it every state has a clean way out, and after it there is none.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType


class State(StrEnum):
    PENDING = "pending"
    CREATED = "created"
    SET = "set"
    VERIFIED = "verified"
    PROMOTED = "promoted"
    QUIESCED = "quiesced"
    REVOKED = "revoked"
    ROLLED_BACK = "rolled_back"
    ABANDONED = "abandoned"


class Event(StrEnum):
    CREATE = "create"
    SET_PASSWORD = "set_password"
    VERIFY_OK = "verify_ok"
    VERIFY_FAILED = "verify_failed"
    PROMOTE = "promote"
    QUIESCE = "quiesce"
    REVOKE = "revoke"
    # ABORT is the clean way out. It is legal only while a rollback is still
    # possible, which means only before PROMOTE.
    ABORT = "abort"
    # GIVE_UP is the dirty way out, legal only after PROMOTE, when the new
    # credential is already in front of consumers and undoing it would be the
    # outage rather than the fix.
    GIVE_UP = "give_up"


#: Every legal (state, event) pair and where it lands. Nothing else is legal.
TRANSITIONS: MappingProxyType[tuple[State, Event], State] = MappingProxyType(
    {
        (State.PENDING, Event.CREATE): State.CREATED,
        (State.PENDING, Event.ABORT): State.ROLLED_BACK,
        (State.CREATED, Event.SET_PASSWORD): State.SET,
        (State.CREATED, Event.ABORT): State.ROLLED_BACK,
        (State.SET, Event.VERIFY_OK): State.VERIFIED,
        (State.SET, Event.VERIFY_FAILED): State.ROLLED_BACK,
        (State.SET, Event.ABORT): State.ROLLED_BACK,
        (State.VERIFIED, Event.PROMOTE): State.PROMOTED,
        (State.VERIFIED, Event.ABORT): State.ROLLED_BACK,
        (State.PROMOTED, Event.QUIESCE): State.QUIESCED,
        (State.PROMOTED, Event.GIVE_UP): State.ABANDONED,
        (State.QUIESCED, Event.REVOKE): State.REVOKED,
        (State.QUIESCED, Event.GIVE_UP): State.ABANDONED,
    }
)

#: States with no outgoing transition. A run that reaches one of these is over.
TERMINAL: frozenset[State] = frozenset({State.REVOKED, State.ROLLED_BACK, State.ABANDONED})

#: The event after which no rollback exists, because consumers can already be
#: resolving the new credential.
POINT_OF_NO_RETURN: Event = Event.PROMOTE

#: The one state in which the old credential stops working. Its only in edge.
DESTRUCTIVE: State = State.REVOKED


class IllegalTransition(Exception):
    """Raised when an event is fired from a state that does not accept it."""

    def __init__(self, state: State, event: Event) -> None:
        self.state = state
        self.event = event
        super().__init__(f"{event} is not legal from {state}")


@dataclass(frozen=True)
class Step:
    """One applied transition, kept for the audit trail and the tests."""

    frm: State
    event: Event
    to: State
    detail: str = ""


@dataclass
class Machine:
    """A single rotation's position in the table above."""

    state: State = State.PENDING
    history: list[Step] = field(default_factory=list)

    @property
    def finished(self) -> bool:
        return self.state in TERMINAL

    @property
    def rolled_forward(self) -> bool:
        """True while this state has no rollback: after the promote, before the end.

        Read off the table rather than off the history, because a machine
        resumed at a state gets the same answer as one replayed from PENDING,
        and GIVE_UP is legal from exactly the states where ABORT is not.
        """
        return Event.GIVE_UP in self.allowed()

    def allowed(self) -> frozenset[Event]:
        return frozenset(event for (state, event) in TRANSITIONS if state is self.state)

    def fire(self, event: Event, detail: str = "") -> Step:
        try:
            destination = TRANSITIONS[(self.state, event)]
        except KeyError:
            raise IllegalTransition(self.state, event) from None
        step = Step(frm=self.state, event=event, to=destination, detail=detail)
        self.state = destination
        self.history.append(step)
        return step

    def bail(self, detail: str = "") -> Step:
        """Leave by whichever exit this state has.

        The caller does not get to choose. Before the promote it is ABORT and
        the rotation undoes itself; after it the only honest answer is to stop
        and page somebody, which is GIVE_UP.
        """
        return self.fire(Event.GIVE_UP if self.rolled_forward else Event.ABORT, detail)
