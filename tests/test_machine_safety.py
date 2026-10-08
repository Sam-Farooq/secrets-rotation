"""The property the whole repo exists for: a failure never revokes.

These tests walk the table rather than running a rotation, because the table is
where the guarantee lives. A new transition added by hand that opens a path
from a failure to REVOKED fails here, without needing a store or a database.
"""

from __future__ import annotations

from rotator.machine import (
    DESTRUCTIVE,
    POINT_OF_NO_RETURN,
    TERMINAL,
    TRANSITIONS,
    Event,
    Machine,
    State,
)

FAILURES = frozenset({Event.ABORT, Event.GIVE_UP, Event.VERIFY_FAILED})


def all_paths() -> list[tuple[tuple[Event, ...], State]]:
    """Every route from PENDING to a terminal state.

    Enumerable because the table is acyclic, which the next test checks rather
    than assumes.
    """
    found: list[tuple[tuple[Event, ...], State]] = []

    def walk(state: State, events: tuple[Event, ...]) -> None:
        if state in TERMINAL:
            found.append((events, state))
            return
        for (frm, event), destination in TRANSITIONS.items():
            if frm is state:
                walk(destination, events + (event,))

    walk(State.PENDING, ())
    return found


def test_the_table_is_acyclic():
    seen: set[State] = set()

    def walk(state: State, stack: tuple[State, ...]) -> None:
        assert state not in stack, f"{state} is reachable from itself via {stack}"
        seen.add(state)
        for (frm, _), destination in TRANSITIONS.items():
            if frm is state:
                walk(destination, stack + (state,))

    walk(State.PENDING, ())
    assert seen == set(State)


def test_there_are_eight_routes_and_one_of_them_revokes():
    paths = all_paths()
    assert len(paths) == 8
    revoking = [events for events, end in paths if end is DESTRUCTIVE]
    assert revoking == [
        (
            Event.CREATE,
            Event.SET_PASSWORD,
            Event.VERIFY_OK,
            Event.PROMOTE,
            Event.QUIESCE,
            Event.REVOKE,
        )
    ]


def test_no_route_containing_a_failure_reaches_revoked():
    for events, end in all_paths():
        if FAILURES & set(events):
            assert end is not DESTRUCTIVE, f"{events} ends in {end}"
            assert end in {State.ROLLED_BACK, State.ABANDONED}


def test_revoked_has_exactly_one_in_edge():
    in_edges = [(frm, event) for (frm, event), to in TRANSITIONS.items() if to is DESTRUCTIVE]
    assert in_edges == [(State.QUIESCED, Event.REVOKE)]


def test_a_failed_verification_cannot_reach_revoked_from_where_it_lands():
    machine = Machine()
    machine.fire(Event.CREATE)
    machine.fire(Event.SET_PASSWORD)
    machine.fire(Event.VERIFY_FAILED)

    assert machine.state is State.ROLLED_BACK
    assert machine.allowed() == frozenset()
    assert DESTRUCTIVE not in reachable_from(machine.state)


def test_abort_is_legal_exactly_while_a_rollback_exists():
    before = {State.PENDING, State.CREATED, State.SET, State.VERIFIED}
    after = {State.PROMOTED, State.QUIESCED}

    for state in before:
        assert Event.ABORT in Machine(state=state).allowed()
        assert Event.GIVE_UP not in Machine(state=state).allowed()
    for state in after:
        assert Event.ABORT not in Machine(state=state).allowed(), (
            f"{state} is past the {POINT_OF_NO_RETURN} and must not offer a rollback"
        )
        assert Event.GIVE_UP in Machine(state=state).allowed()


def test_every_live_state_has_an_exit_that_does_not_revoke():
    for state in set(State) - TERMINAL:
        machine = Machine(state=state)
        machine.bail("something broke")
        assert machine.state in {State.ROLLED_BACK, State.ABANDONED}
        assert machine.state is not DESTRUCTIVE


def test_bail_picks_the_rollback_before_promote_and_the_page_after():
    early = Machine()
    early.fire(Event.CREATE)
    early.bail("stage failed")
    assert early.history[-1].event is Event.ABORT
    assert early.state is State.ROLLED_BACK

    late = Machine()
    for event in (Event.CREATE, Event.SET_PASSWORD, Event.VERIFY_OK, Event.PROMOTE):
        late.fire(event)
    late.bail("revoke failed")
    assert late.history[-1].event is Event.GIVE_UP
    assert late.state is State.ABANDONED


def reachable_from(start: State) -> set[State]:
    seen = {start}
    frontier = [start]
    while frontier:
        state = frontier.pop()
        for (frm, _), destination in TRANSITIONS.items():
            if frm is state and destination not in seen:
                seen.add(destination)
                frontier.append(destination)
    return seen
