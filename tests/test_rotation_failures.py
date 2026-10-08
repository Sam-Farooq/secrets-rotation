"""Every way a rotation stops, and what it left behind.

The one that matters is the first: a credential that does not authenticate must
not cause the working one to be revoked.
"""

from __future__ import annotations

import json

from fakes import FakeClock, FakeDatabase

from rotator.audit import MemoryAudit
from rotator.machine import Event, State
from rotator.rotation import Rotation
from rotator.stores import SecretsManagerStore


def run(config, client, database, target="orders-db", audit=None, clock=None):
    return Rotation(
        target=config.target(target),
        store=SecretsManagerStore(client, allowed_secret_ids=config.secret_ids),
        admin=database,
        clock=clock or FakeClock(),
        audit=audit,
    ).run()


def live_credential(client, secret_id):
    return json.loads(
        client.get_secret_value(SecretId=secret_id, VersionStage="AWSCURRENT")["SecretString"]
    )


def test_a_failed_verification_revokes_nothing(config, secretsmanager, seeded_secret):
    database = FakeDatabase({"orders_app_a": "the-old-one"}, reject=("orders_app_b",))

    outcome = run(config, secretsmanager, database)

    assert outcome.state is State.ROLLED_BACK
    assert not outcome.ok
    assert outcome.revoked is None
    assert outcome.rotated_to is None
    assert "revoke" not in {name for name, _ in database.calls}
    # The credential consumers hold is the one they held before.
    assert live_credential(secretsmanager, seeded_secret) == {
        "username": "orders_app_a",
        "password": "the-old-one",
    }
    assert database.works("orders_app_a", "the-old-one")


def test_a_failed_verification_leaves_nothing_staged(config, secretsmanager, seeded_secret):
    database = FakeDatabase({"orders_app_a": "the-old-one"}, reject=("orders_app_b",))
    store = SecretsManagerStore(secretsmanager, allowed_secret_ids=config.secret_ids)

    Rotation(
        target=config.target("orders-db"),
        store=store,
        admin=database,
        clock=FakeClock(),
    ).run()

    assert store.staged(seeded_secret) is None


def test_a_failed_verification_does_not_wait_out_the_quiesce_window(
    config, secretsmanager, seeded_secret
):
    clock = FakeClock()
    database = FakeDatabase({"orders_app_a": "the-old-one"}, reject=("orders_app_b",))

    run(config, secretsmanager, database, clock=clock)

    # Two retry delays and no quiesce. A rollback that sleeps for fifteen
    # minutes is fifteen minutes of a scheduled task doing nothing.
    assert 900 not in clock.sleeps
    assert len(clock.sleeps) == config.target("orders-db").verify_attempts - 1


def test_the_rollback_says_why_in_the_audit(config, secretsmanager, seeded_secret):
    audit = MemoryAudit()
    database = FakeDatabase({"orders_app_a": "the-old-one"}, reject=("orders_app_b",))

    run(config, secretsmanager, database, audit=audit)

    last = audit.lines[-1]
    assert last["event"] == "verify_failed"
    assert last["to"] == "rolled_back"
    assert "did not authenticate after 3 attempts" in last["detail"]


def test_a_database_that_refuses_the_alter_role_rolls_back(config, secretsmanager, seeded_secret):
    database = FakeDatabase({"orders_app_a": "the-old-one"}, fail_set=("orders_app_b",))

    outcome = run(config, secretsmanager, database)

    assert outcome.state is State.ROLLED_BACK
    assert outcome.history[-1].event is Event.ABORT
    assert "PermissionDenied" in outcome.reason
    assert database.did("verify") == ()


def test_a_revoke_that_fails_is_abandoned_and_not_retried(config, secretsmanager, seeded_secret):
    """Past the promote there is no rollback.

    Consumers are already resolving the new credential, so putting the old one
    back would be the outage. The run stops and says so.
    """
    database = FakeDatabase({"orders_app_a": "the-old-one"}, fail_revoke=("orders_app_a",))

    outcome = run(config, secretsmanager, database)

    assert outcome.state is State.ABANDONED
    assert outcome.needs_a_human
    assert outcome.rotated_to == "orders_app_b"
    assert outcome.revoked is None
    assert outcome.history[-1].event is Event.GIVE_UP
    # The new credential is published and working. That part is not undone.
    assert live_credential(secretsmanager, seeded_secret)["username"] == "orders_app_b"
    assert database.did("revoke") == ("orders_app_a",)


def test_an_abandoned_run_does_not_discard_what_it_published(config, secretsmanager, seeded_secret):
    database = FakeDatabase({"orders_app_a": "the-old-one"}, fail_revoke=("orders_app_a",))
    store = SecretsManagerStore(secretsmanager, allowed_secret_ids=config.secret_ids)

    Rotation(
        target=config.target("orders-db"),
        store=store,
        admin=database,
        clock=FakeClock(),
    ).run()

    assert store.current(seeded_secret).username == "orders_app_b"
    assert store.staged(seeded_secret) is None


def test_a_leftover_staged_credential_stops_the_next_run(config, secretsmanager, seeded_secret):
    store = SecretsManagerStore(secretsmanager, allowed_secret_ids=config.secret_ids)
    from rotator.ports import Credential

    store.stage(seeded_secret, Credential("orders_app_b", "half-finished"))
    database = FakeDatabase({"orders_app_a": "the-old-one"})

    outcome = run(config, secretsmanager, database)

    assert outcome.state is State.ROLLED_BACK
    assert "already has a staged credential" in outcome.reason
    assert "rotator discard orders-db" in outcome.reason
    assert database.calls == []


def test_a_secret_that_does_not_exist_is_not_created(config, secretsmanager):
    """This tool rotates. Creating the first credential is Terraform's job, and
    a tool that would create one on a typo creates it in the wrong place."""
    database = FakeDatabase({})

    outcome = run(config, secretsmanager, database)

    assert outcome.state is State.ROLLED_BACK
    assert "will not create the first one" in outcome.reason
    assert database.calls == []


def test_a_live_credential_for_an_undeclared_user_stops_before_touching_anything(
    config, secretsmanager
):
    secretsmanager.create_secret(
        Name="prod/orders/app",
        SecretString=json.dumps({"username": "postgres", "password": "x"}),
    )
    database = FakeDatabase({"postgres": "x"})

    outcome = run(config, secretsmanager, database)

    assert outcome.state is State.ROLLED_BACK
    assert "not one of the declared users" in outcome.reason
    assert database.calls == []
