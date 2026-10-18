"""A rotation handles two passwords. Neither may reach a log line.

The audit file is written by a scheduled task and shipped somewhere central, so
a password in it outlives the rotation that was meant to retire it. These tests
run a real rotation with a known password and then grep everything the run
produced.
"""

from __future__ import annotations

import json

from fakes import FakeClock, FakeDatabase

from rotator.audit import FileAudit, MemoryAudit
from rotator.machine import Event, Machine
from rotator.ports import Credential
from rotator.rotation import Rotation
from rotator.stores import SecretsManagerStore

KNOWN = "a-password-nobody-would-choose-9f3c"


def rotate(config, client, database, audit, clock=None):
    return Rotation(
        target=config.target("orders-db"),
        store=SecretsManagerStore(client, allowed_secret_ids=config.secret_ids),
        admin=database,
        clock=clock or FakeClock(),
        audit=audit,
        make_password=lambda length: KNOWN,
    ).run()


def test_a_credential_does_not_print_its_password():
    credential = Credential("orders_app_a", KNOWN)

    assert KNOWN not in repr(credential)
    assert KNOWN not in str(credential)
    assert KNOWN not in f"{credential}"
    assert KNOWN not in json.dumps({"c": repr(credential)})
    assert "redacted" in repr(credential)
    # The username is not a secret and is the only thing worth logging.
    assert "orders_app_a" in repr(credential)


def test_the_password_is_still_reachable_for_the_code_that_needs_it():
    credential = Credential("orders_app_a", KNOWN)

    assert credential.password == KNOWN


def test_the_audit_of_a_successful_run_holds_no_password(config, secretsmanager, seeded_secret):
    audit = MemoryAudit()
    database = FakeDatabase({"orders_app_a": "the-old-one", "orders_app_b": "the-standby-one"})

    outcome = rotate(config, secretsmanager, database, audit)

    assert outcome.ok
    written = json.dumps(audit.lines)
    assert KNOWN not in written
    assert "the-old-one" not in written


def test_the_audit_of_a_failed_run_holds_no_password(config, secretsmanager, seeded_secret):
    audit = MemoryAudit()
    database = FakeDatabase(
        {"orders_app_a": "the-old-one", "orders_app_b": "the-standby-one"}, reject=("orders_app_b",)
    )

    rotate(config, secretsmanager, database, audit)

    assert KNOWN not in json.dumps(audit.lines)


def test_the_outcome_summary_holds_no_password(config, secretsmanager, seeded_secret):
    database = FakeDatabase(
        {"orders_app_a": "the-old-one", "orders_app_b": "the-standby-one"},
        fail_set=("orders_app_b",),
    )

    outcome = rotate(config, secretsmanager, database, MemoryAudit())

    assert KNOWN not in outcome.summary()
    assert KNOWN not in outcome.reason
    assert KNOWN not in repr(outcome)


def test_the_file_audit_appends_one_json_line_per_transition(
    config, secretsmanager, seeded_secret, tmp_path
):
    path = tmp_path / "nested" / "orders-db.audit.jsonl"
    database = FakeDatabase({"orders_app_a": "the-old-one", "orders_app_b": "the-standby-one"})

    outcome = rotate(config, secretsmanager, database, FileAudit(path))

    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == len(outcome.history)
    assert [line["event"] for line in lines] == [str(step.event) for step in outcome.history]
    assert {line["target"] for line in lines} == {"orders-db"}
    assert KNOWN not in path.read_text(encoding="utf-8")


def test_the_last_audit_line_names_the_state_the_runbooks_key_off(
    config, secretsmanager, seeded_secret, tmp_path
):
    path = tmp_path / "orders-db.audit.jsonl"
    database = FakeDatabase(
        {"orders_app_a": "the-old-one", "orders_app_b": "the-standby-one"},
        fail_revoke=("orders_app_a",),
    )

    rotate(config, secretsmanager, database, FileAudit(path))

    last = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
    assert last["to"] == "abandoned"
    assert last["ok"] is False


def test_the_audit_timestamp_comes_from_the_clock(config, secretsmanager, seeded_secret):
    audit = MemoryAudit()
    clock = FakeClock()
    database = FakeDatabase({"orders_app_a": "the-old-one", "orders_app_b": "the-standby-one"})

    rotate(config, secretsmanager, database, audit, clock)

    assert audit.lines[0]["at"] == "2026-03-01T03:15:00+00:00"
    # The quiesce window moved the clock, so the revoke is logged later than
    # the promote. An audit where every line shares a timestamp cannot show
    # how long a run sat between the two.
    assert audit.lines[-1]["at"] > audit.lines[0]["at"]


def test_a_step_detail_is_optional_and_absent_rather_than_empty():
    audit = MemoryAudit()
    machine = Machine()
    step = machine.fire(Event.CREATE)

    audit.record("orders-db", step, FakeClock().now())

    assert "detail" not in audit.lines[0]
