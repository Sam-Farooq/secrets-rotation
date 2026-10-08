"""The dry run, held to its word at the boto3 layer.

A comment claiming a function does not write is worth nothing. This records the
operation names botocore actually sends during a plan and compares them against
the allowlist in the store module.
"""

from __future__ import annotations

from typing import Any

from fakes import FakeClock, FakeVaultTransport, RecordingStore

from rotator.rotation import plan
from rotator.stores import READ_ONLY_OPERATIONS, SecretsManagerStore, VaultKvStore


def recorded_operations(client: Any) -> list[str]:
    seen: list[str] = []
    client.meta.events.register(
        "before-call.secrets-manager", lambda model=None, **kwargs: seen.append(model.name)
    )
    return seen


def test_a_plan_sends_only_read_operations(config, secretsmanager, seeded_secret):
    sent = recorded_operations(secretsmanager)
    store = SecretsManagerStore(secretsmanager, allowed_secret_ids=config.secret_ids)

    plan(config.target("orders-db"), store, FakeClock().now())

    assert sent, "the plan made no AWS calls at all, so this proves nothing"
    assert set(sent) <= READ_ONLY_OPERATIONS, (
        f"a plan sent {sorted(set(sent) - READ_ONLY_OPERATIONS)}"
    )


def test_the_allowlist_itself_has_no_writes():
    writes = {"PutSecretValue", "UpdateSecretVersionStage", "CreateSecret", "DeleteSecret"}
    assert READ_ONLY_OPERATIONS & writes == set()


def test_a_plan_against_vault_writes_nothing_either(config):
    transport = FakeVaultTransport()
    transport.seed(
        "kv/analytics/app",
        {
            "current": {"username": "analytics_app_a", "password": "x"},
            "rotated_at": "2026-01-15T03:15:00+00:00",
        },
    )
    store = RecordingStore(VaultKvStore(transport, clock=FakeClock()))

    plan(config.target("analytics-db"), store, FakeClock().now())

    assert transport.writes == 0
    assert set(store.calls) <= {"current", "staged", "current_age"}


def test_a_due_target_is_reported_as_due(config, secretsmanager, seeded_secret):
    import datetime as dt

    store = SecretsManagerStore(secretsmanager, allowed_secret_ids=config.secret_ids)
    later = dt.datetime.now(dt.UTC) + dt.timedelta(days=31)

    row = plan(config.target("orders-db"), store, later)

    assert row.due
    assert row.verdict == "due"
    assert row.current_username == "orders_app_a"
    assert row.next_username == "orders_app_b"
    assert row.age_days is not None and row.age_days > 30


def test_a_fresh_target_is_not_due(config, secretsmanager, seeded_secret):
    store = SecretsManagerStore(secretsmanager, allowed_secret_ids=config.secret_ids)

    row = plan(config.target("orders-db"), store, FakeClock().now())

    assert not row.due
    assert row.verdict == "ok"


def test_a_staged_credential_blocks_the_plan_rather_than_clearing_it(
    config, secretsmanager, seeded_secret
):
    from rotator.ports import Credential

    store = SecretsManagerStore(secretsmanager, allowed_secret_ids=config.secret_ids)
    store.stage(seeded_secret, Credential("orders_app_b", "half-finished"))
    sent = recorded_operations(secretsmanager)

    row = plan(config.target("orders-db"), store, FakeClock().now())

    assert row.verdict == "blocked"
    assert not row.due
    assert any("stopped" in blocker for blocker in row.blockers)
    assert set(sent) <= READ_ONLY_OPERATIONS


def test_an_undeclared_live_user_is_a_blocker_not_an_exception(config, secretsmanager):
    import json

    secretsmanager.create_secret(
        Name="prod/orders/app",
        SecretString=json.dumps({"username": "postgres", "password": "x"}),
    )
    store = SecretsManagerStore(secretsmanager, allowed_secret_ids=config.secret_ids)

    row = plan(config.target("orders-db"), store, FakeClock().now())

    assert row.verdict == "blocked"
    assert row.current_username == "postgres"
    assert row.next_username is None
