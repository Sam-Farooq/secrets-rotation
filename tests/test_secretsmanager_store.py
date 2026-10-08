"""The store, against moto.

This is the one adapter with a real implementation under test, because the
staging label mechanics are the part of this repo most likely to be wrong in a
way reading the code does not reveal.
"""

from __future__ import annotations

import datetime as dt
import json

import pytest

from rotator.errors import Refused, StoreError
from rotator.ports import Credential
from rotator.stores import SecretsManagerStore

NEW = Credential("orders_app_b", "a-new-password")


@pytest.fixture
def store(secretsmanager):
    return SecretsManagerStore(secretsmanager, allowed_secret_ids=("prod/orders/app",))


def test_current_reads_the_label_consumers_read(store, seeded_secret):
    assert store.current(seeded_secret) == Credential("orders_app_a", "the-old-one")


def test_a_secret_outside_targets_toml_is_refused_before_a_call(store):
    with pytest.raises(Refused) as caught:
        store.current("prod/somebody-elses/app")

    assert "not declared in targets.toml" in str(caught.value)


def test_staging_is_invisible_to_consumers(store, secretsmanager, seeded_secret):
    store.stage(seeded_secret, NEW)

    assert store.staged(seeded_secret) == NEW
    assert store.current(seeded_secret).username == "orders_app_a"


def test_promote_puts_the_new_credential_in_front_of_consumers(store, seeded_secret):
    store.stage(seeded_secret, NEW)
    store.promote(seeded_secret)

    assert store.current(seeded_secret) == NEW


def test_the_replaced_version_becomes_awsprevious(store, secretsmanager, seeded_secret):
    """A rollback target, right up to the moment revoke runs and the password
    in it stops working."""
    store.stage(seeded_secret, NEW)
    store.promote(seeded_secret)

    previous = json.loads(
        secretsmanager.get_secret_value(SecretId=seeded_secret, VersionStage="AWSPREVIOUS")[
            "SecretString"
        ]
    )
    assert previous["username"] == "orders_app_a"


def test_promote_with_nothing_staged_says_so(store, seeded_secret):
    with pytest.raises(StoreError, match="nothing is staged"):
        store.promote(seeded_secret)


def test_discard_is_safe_to_call_twice(store, seeded_secret):
    store.stage(seeded_secret, NEW)
    store.discard_staged(seeded_secret)
    store.discard_staged(seeded_secret)

    assert store.staged(seeded_secret) is None
    assert store.current(seeded_secret).username == "orders_app_a"


def test_staging_twice_leaves_one_pending_version(store, secretsmanager, seeded_secret):
    store.stage(seeded_secret, NEW)
    store.stage(seeded_secret, Credential("orders_app_b", "a-third-password"))

    stages = secretsmanager.describe_secret(SecretId=seeded_secret)["VersionIdsToStages"]
    pending = [v for v, labels in stages.items() if "AWSPENDING" in labels]
    assert len(pending) == 1
    assert store.staged(seeded_secret).password == "a-third-password"


def test_age_comes_from_the_current_version_not_the_secret(store, seeded_secret):
    """describe_secret's LastChangedDate moves when a pending version is
    written, so it reports a month old password as new the moment a rotation
    starts. The age that matters is the age of the version carrying
    AWSCURRENT."""
    now = dt.datetime.now(dt.UTC) + dt.timedelta(days=40)

    before = store.current_age(seeded_secret, now)
    store.stage(seeded_secret, NEW)
    after = store.current_age(seeded_secret, now)

    assert before is not None
    assert before > dt.timedelta(days=39)
    assert after == before


def test_age_resets_after_a_promote(store, seeded_secret):
    real_now = dt.datetime.now(dt.UTC)
    before = store.current_age(seeded_secret, real_now + dt.timedelta(days=40))

    store.stage(seeded_secret, NEW)
    store.promote(seeded_secret)
    after = store.current_age(seeded_secret, real_now)

    assert before > dt.timedelta(days=39)
    assert after < dt.timedelta(minutes=1)


def test_a_secret_that_is_not_json_is_an_error_naming_the_stage(store, secretsmanager):
    secretsmanager.create_secret(Name="prod/orders/app", SecretString="not json at all")

    with pytest.raises(StoreError, match="AWSCURRENT is not JSON"):
        store.current("prod/orders/app")


def test_a_missing_key_is_named_and_the_value_is_not(store, secretsmanager):
    secretsmanager.create_secret(
        Name="prod/orders/app",
        SecretString=json.dumps({"user": "orders_app_a", "password": "hunter2"}),
    )

    with pytest.raises(StoreError) as caught:
        store.current("prod/orders/app")

    assert "has no 'username' key" in str(caught.value)
    assert "hunter2" not in str(caught.value)


def test_a_missing_secret_reads_as_absent_rather_than_raising(store):
    assert store.current("prod/orders/app") is None
    assert store.staged("prod/orders/app") is None
    assert store.current_age("prod/orders/app", dt.datetime.now(dt.UTC)) is None
