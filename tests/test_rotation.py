"""A whole rotation, Secrets Manager under moto and the database faked."""

from __future__ import annotations

import json

from fakes import FakeClock, FakeDatabase

from rotator.audit import MemoryAudit
from rotator.machine import Event, State
from rotator.rotation import Rotation
from rotator.stores import SecretsManagerStore


def rotation(config, client, database, clock, audit=None, target="orders-db"):
    return Rotation(
        target=config.target(target),
        store=SecretsManagerStore(client, allowed_secret_ids=config.secret_ids),
        admin=database,
        clock=clock,
        audit=audit,
    )


def test_the_inactive_user_is_the_one_that_changes(config, secretsmanager, seeded_secret):
    database = FakeDatabase({"orders_app_a": "the-old-one", "orders_app_b": "whatever"})
    clock = FakeClock()

    outcome = rotation(config, secretsmanager, database, clock).run()

    assert outcome.ok
    assert outcome.state is State.REVOKED
    # Only the user nobody was connecting as had its password set.
    assert database.did("set_password") == ("orders_app_b",)
    assert outcome.rotated_to == "orders_app_b"
    assert outcome.revoked == "orders_app_a"


def test_consumers_read_the_new_credential_and_it_works(config, secretsmanager, seeded_secret):
    database = FakeDatabase({"orders_app_a": "the-old-one", "orders_app_b": "the-standby-one"})

    rotation(config, secretsmanager, database, FakeClock()).run()

    live = json.loads(
        secretsmanager.get_secret_value(SecretId=seeded_secret, VersionStage="AWSCURRENT")[
            "SecretString"
        ]
    )
    assert live["username"] == "orders_app_b"
    assert database.works("orders_app_b", live["password"])
    # And the password it replaced is dead.
    assert not database.works("orders_app_a", "the-old-one")


def test_the_order_is_verify_then_promote_then_revoke(config, secretsmanager, seeded_secret):
    database = FakeDatabase({"orders_app_a": "the-old-one", "orders_app_b": "the-standby-one"})
    audit = MemoryAudit()

    outcome = rotation(config, secretsmanager, database, FakeClock(), audit).run()

    assert [step.event for step in outcome.history] == [
        Event.CREATE,
        Event.SET_PASSWORD,
        Event.VERIFY_OK,
        Event.PROMOTE,
        Event.QUIESCE,
        Event.REVOKE,
    ]
    # The revoke is the last thing the database is asked to do, after the
    # verify that proved the replacement works.
    assert database.calls[-1] == ("revoke", "orders_app_a")
    assert [line["event"] for line in audit.lines] == [str(step.event) for step in outcome.history]


def test_the_quiesce_window_is_actually_waited_for(config, secretsmanager, seeded_secret):
    clock = FakeClock()
    database = FakeDatabase({"orders_app_a": "the-old-one", "orders_app_b": "the-standby-one"})

    rotation(config, secretsmanager, database, clock).run()

    assert config.target("orders-db").quiesce_seconds in clock.sleeps
    assert sum(clock.sleeps) >= 900


def test_nothing_is_staged_once_it_is_over(config, secretsmanager, seeded_secret):
    """The bug that made promote a two call operation.

    Moving AWSCURRENT leaves AWSPENDING attached to the same version, so after
    a clean rotation the target still looked half finished and the next run
    refused to start.
    """
    database = FakeDatabase({"orders_app_a": "the-old-one", "orders_app_b": "the-standby-one"})
    store = SecretsManagerStore(secretsmanager, allowed_secret_ids=config.secret_ids)

    Rotation(
        target=config.target("orders-db"),
        store=store,
        admin=database,
        clock=FakeClock(),
    ).run()

    assert store.staged(seeded_secret) is None
    stages = secretsmanager.describe_secret(SecretId=seeded_secret)["VersionIdsToStages"]
    assert not any("AWSPENDING" in labels for labels in stages.values())


def test_a_second_rotation_goes_back_to_the_first_user(config, secretsmanager, seeded_secret):
    database = FakeDatabase({"orders_app_a": "the-old-one", "orders_app_b": "the-standby-one"})

    first = rotation(config, secretsmanager, database, FakeClock()).run()
    second = rotation(config, secretsmanager, database, FakeClock()).run()

    assert first.rotated_to == "orders_app_b"
    assert second.rotated_to == "orders_app_a"
    assert second.ok


def test_a_verify_that_fails_twice_and_then_passes_still_rotates(
    config, secretsmanager, seeded_secret
):
    """A verify routed to a read replica can fail before the ALTER ROLE has
    arrived there, so the attempt count is not decoration."""
    database = FakeDatabase(
        {"orders_app_a": "the-old-one", "orders_app_b": "the-standby-one"}, transient=2
    )
    clock = FakeClock()

    outcome = rotation(config, secretsmanager, database, clock).run()

    assert outcome.ok
    assert database.did("verify") == ("orders_app_b",) * 3
    assert clock.sleeps[:2] == [5.0, 5.0] or clock.sleeps[:2] == [5, 5]
