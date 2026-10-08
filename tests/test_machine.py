"""The transition table, checked as a table."""

from __future__ import annotations

import pytest

from rotator.machine import (
    TERMINAL,
    TRANSITIONS,
    Event,
    IllegalTransition,
    Machine,
    State,
)


def test_the_table_has_the_shape_the_readme_quotes():
    assert len(State) == 9
    assert len(TRANSITIONS) == 13
    assert set(TERMINAL) == {State.REVOKED, State.ROLLED_BACK, State.ABANDONED}


def test_every_state_appears_in_the_table():
    mentioned = {state for state, _ in TRANSITIONS} | set(TRANSITIONS.values())
    assert mentioned == set(State)


def test_terminal_states_have_no_way_out():
    for state in TERMINAL:
        assert Machine(state=state).allowed() == frozenset()
        assert Machine(state=state).finished


def test_allowed_agrees_with_the_table():
    for state in State:
        expected = frozenset(event for (frm, event) in TRANSITIONS if frm is state)
        assert Machine(state=state).allowed() == expected


def test_firing_records_both_sides_and_the_detail():
    machine = Machine()
    step = machine.fire(Event.CREATE, "staged a password for orders_app_b")

    assert (step.frm, step.event, step.to) == (State.PENDING, Event.CREATE, State.CREATED)
    assert step.detail == "staged a password for orders_app_b"
    assert machine.state is State.CREATED
    assert machine.history == [step]


def test_an_illegal_event_names_the_state_and_the_event():
    machine = Machine()

    with pytest.raises(IllegalTransition) as caught:
        machine.fire(Event.REVOKE)

    assert caught.value.state is State.PENDING
    assert caught.value.event is Event.REVOKE
    assert "revoke is not legal from pending" in str(caught.value)
    # The failed event leaves nothing behind.
    assert machine.state is State.PENDING
    assert machine.history == []


def test_rolled_forward_flips_at_the_promote_and_not_before():
    machine = Machine()
    for event in (Event.CREATE, Event.SET_PASSWORD, Event.VERIFY_OK):
        machine.fire(event)
        assert not machine.rolled_forward

    machine.fire(Event.PROMOTE)
    assert machine.rolled_forward
