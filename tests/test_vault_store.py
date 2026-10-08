"""Vault KV v2 against a hand written transport.

The transport is a dict with a version counter and the one behaviour that
matters, check and set. Nothing was captured from a Vault server.
"""

from __future__ import annotations

import datetime as dt

import pytest
from fakes import START, FakeClock, FakeVaultTransport

from rotator.errors import StoreError
from rotator.ports import Credential
from rotator.stores import VaultKvStore

KEY = "kv/analytics/app"
PATH = "kv/analytics/app"
NEW = Credential("analytics_app_b", "a-new-password")


@pytest.fixture
def transport():
    fake = FakeVaultTransport()
    fake.seed(
        PATH,
        {
            "current": {"username": "analytics_app_a", "password": "the-old-one"},
            "rotated_at": "2026-01-15T03:15:00+00:00",
        },
    )
    return fake


@pytest.fixture
def store(transport):
    return VaultKvStore(transport, clock=FakeClock())


def test_current_and_staged_live_in_the_same_document(store):
    assert store.current(KEY) == Credential("analytics_app_a", "the-old-one")
    assert store.staged(KEY) is None

    store.stage(KEY, NEW)

    assert store.staged(KEY) == NEW
    assert store.current(KEY).username == "analytics_app_a"


def test_promote_moves_pending_into_current_and_keeps_the_old_one(store, transport):
    store.stage(KEY, NEW)
    store.promote(KEY)

    assert store.current(KEY) == NEW
    assert store.staged(KEY) is None
    assert transport.documents[PATH]["previous"]["username"] == "analytics_app_a"


def test_promote_stamps_the_rotation_time_from_the_injected_clock(store, transport):
    store.stage(KEY, NEW)
    store.promote(KEY)

    assert transport.documents[PATH]["rotated_at"] == START.isoformat()


def test_a_writer_landing_between_the_read_and_the_write_is_rejected(store, transport):
    """What check and set is for.

    KV v2 has no staging labels, so staging a credential is read the document,
    add a field, write it back. Two rotators doing that at once would have the
    second overwrite the first. `options.cas` carries the version that was
    read, so the second write is a 400 instead.
    """
    transport.race_next_read = True

    with pytest.raises(StoreError, match="check-and-set"):
        store.stage(KEY, NEW)

    assert store.staged(KEY) is None


def test_a_normal_write_carries_the_version_it_read(store, transport):
    before = transport.versions[PATH]

    store.stage(KEY, NEW)

    assert transport.versions[PATH] == before + 1
    assert transport.writes == 1


def test_discard_removes_only_the_pending_field(store, transport):
    store.stage(KEY, NEW)
    store.discard_staged(KEY)

    assert store.staged(KEY) is None
    assert store.current(KEY).username == "analytics_app_a"
    assert "rotated_at" in transport.documents[PATH]


def test_discard_with_nothing_staged_writes_nothing(store, transport):
    before = transport.writes

    store.discard_staged(KEY)

    assert transport.writes == before


def test_age_is_read_from_the_field_the_rotator_writes(store):
    now = dt.datetime(2026, 2, 14, 3, 15, tzinfo=dt.UTC)

    assert store.current_age(KEY, now) == dt.timedelta(days=30)


def test_a_secret_seeded_by_hand_has_an_unknown_age(transport):
    transport.seed(PATH, {"current": {"username": "analytics_app_a", "password": "x"}})
    store = VaultKvStore(transport, clock=FakeClock())

    assert store.current_age(KEY, dt.datetime.now(dt.UTC)) is None


def test_a_missing_document_reads_as_absent(store):
    assert store.current("kv/nothing/here") is None


def test_a_key_without_a_mount_is_rejected(store):
    with pytest.raises(StoreError, match="is not <mount>/<path>"):
        store.current("justapath")


def test_promote_with_nothing_staged_says_so(store):
    with pytest.raises(StoreError, match="nothing is staged"):
        store.promote(KEY)
