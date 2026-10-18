"""One set of tests, run against the fake transport and against a real Vault.

`tests/fakes.py` is what the whole suite stages and promotes against, so
everything the Vault store is known to do is known through it. These tests are
the ones that say the fake is a faithful stand-in rather than a convenient
one: each runs twice, once against `FakeVaultTransport` and once against a
Vault over HTTP, and both have to agree.

The live half is marked `live_vault` and is deselected unless asked for, so
the default run stays offline and needs neither Docker nor a server:

    pytest                    the fake only, no network
    pytest -m live_vault      the real server, needs ROTATOR_TEST_VAULT_ADDR
    pytest -m ""              both

The same arrangement as tests/test_database_admin_contract.py, and it found
the same kind of thing: two states the fake could not produce, and in both of
them the real failure was reported as something else.
"""

from __future__ import annotations

import datetime as dt

import live_vault as live
import pytest
from fakes import START, FakeClock, FakeVaultTransport, RacingTransport

from rotator.errors import StoreError
from rotator.ports import Credential
from rotator.stores import VaultKvStore

NEW = Credential("analytics_app_b", "a-new-password")
SEEDED = {
    "current": {"username": "analytics_app_a", "password": "the-old-one"},
    "rotated_at": "2026-01-15T03:15:00+00:00",
}


class FakeHarness:
    name = "fake"
    missing_mount_key = "nosuchmount/analytics/app"

    def setup(self):
        self.inner = FakeVaultTransport()
        self.key = "kv/analytics/app"
        self.inner.seed(self.key, SEEDED)
        self.transport = RacingTransport(self.inner)
        self.store = VaultKvStore(self.transport, clock=FakeClock())
        return self

    def version(self) -> int:
        return self.inner.versions.get(self.key, 0)

    def soft_delete(self) -> None:
        self.inner.soft_delete(self.key)

    def teardown(self) -> None:
        pass


class LiveHarness:
    name = "live"

    def setup(self):
        live.requires_kv_v2()
        self.document = live.Document()
        self.document.seed(SEEDED)
        self.key = self.document.key
        self.missing_mount_key = "rotator-no-such-mount/analytics/app"
        self.transport = RacingTransport(live.transport())
        self.store = VaultKvStore(self.transport, clock=FakeClock())
        return self

    def version(self) -> int:
        return self.document.version()

    def soft_delete(self) -> None:
        self.document.soft_delete()

    def teardown(self) -> None:
        self.document.drop()


@pytest.fixture(params=[FakeHarness, pytest.param(LiveHarness, marks=pytest.mark.live_vault)])
def backend(request):
    harness = request.param().setup()
    yield harness
    harness.teardown()


def test_current_and_staged_live_in_the_same_document(backend):
    assert backend.store.current(backend.key) == Credential("analytics_app_a", "the-old-one")
    assert backend.store.staged(backend.key) is None

    backend.store.stage(backend.key, NEW)

    assert backend.store.staged(backend.key) == NEW
    assert backend.store.current(backend.key).username == "analytics_app_a"


def test_promote_moves_pending_into_current_and_keeps_the_previous(backend):
    backend.store.stage(backend.key, NEW)
    backend.store.promote(backend.key)

    assert backend.store.current(backend.key) == NEW
    assert backend.store.staged(backend.key) is None


def test_promote_stamps_the_rotation_time_from_the_injected_clock(backend):
    backend.store.stage(backend.key, NEW)
    backend.store.promote(backend.key)

    assert backend.store.current_age(backend.key, START) == dt.timedelta(0)


def test_promote_with_nothing_staged_says_so(backend):
    with pytest.raises(StoreError, match="nothing is staged"):
        backend.store.promote(backend.key)


def test_discard_removes_only_the_pending_field(backend):
    backend.store.stage(backend.key, NEW)
    backend.store.discard_staged(backend.key)

    assert backend.store.staged(backend.key) is None
    assert backend.store.current(backend.key).username == "analytics_app_a"
    assert backend.store.current_age(backend.key, START) is not None


def test_discard_with_nothing_staged_writes_nothing(backend):
    before = backend.version()

    backend.store.discard_staged(backend.key)

    assert backend.version() == before


def test_a_write_advances_the_version_and_reports_the_one_it_made(backend):
    before = backend.version()

    staged = backend.store.stage(backend.key, NEW)

    assert backend.version() == before + 1
    assert staged == str(before + 1)


def test_a_writer_landing_between_the_read_and_the_write_is_rejected(backend):
    """What check and set is for.

    KV v2 has no staging labels, so staging a credential is read the document,
    add a field, write it back. Two rotators doing that at once would have the
    second overwrite the first. `options.cas` carries the version that was
    read, so the second write is a 400 instead.

    On the live backend the competing write is a real one, against the same
    path, and the 400 is Vault's.
    """
    backend.transport.arm()

    with pytest.raises(StoreError, match="check-and-set"):
        backend.store.stage(backend.key, NEW)

    assert backend.store.staged(backend.key) is None


def test_a_missing_document_reads_as_absent(backend):
    mount = backend.key.split("/", 1)[0]
    assert backend.store.current(f"{mount}/nothing/here") is None


def test_a_key_without_a_mount_is_rejected(backend):
    with pytest.raises(StoreError, match="is not <mount>/<path>"):
        backend.store.current("justapath")


def test_a_mount_that_does_not_exist_is_not_an_absent_secret(backend):
    """The first thing the live run disagreed about.

    Vault answers an unknown mount with a 404, the same status as a secret
    that is not there, and the transport read both as "nothing here". So a
    typo in `vault_mount` produced a plan reporting the target had never been
    rotated, and the next step would have staged a credential into a path no
    consumer reads. The two 404s differ in the body, which is now read.
    """
    with pytest.raises(StoreError, match="no handler for route"):
        backend.store.current(backend.missing_mount_key)


def test_a_soft_deleted_version_reads_as_absent_and_the_next_write_still_lands(backend):
    """The second thing it disagreed about, and the worse of the two.

    `vault kv delete` removes the latest version and keeps its number. The
    read answers 404 carrying the metadata, the transport threw the body away,
    and the write that followed sent `cas: 0` against a path whose version was
    two. Vault refused it with "check-and-set parameter did not match", so a
    deleted secret was reported to the operator as a concurrent rotation.
    """
    backend.store.stage(backend.key, NEW)
    deleted_at = backend.version()

    backend.soft_delete()

    assert backend.store.current(backend.key) is None
    assert backend.store.staged(backend.key) is None
    assert backend.store.stage(backend.key, NEW) == str(deleted_at + 1)
    assert backend.store.staged(backend.key) == NEW


def test_age_is_read_from_the_field_the_rotator_writes(backend):
    now = dt.datetime(2026, 2, 14, 3, 15, tzinfo=dt.UTC)

    assert backend.store.current_age(backend.key, now) == dt.timedelta(days=30)


def test_a_credential_without_a_password_names_the_key_that_is_missing(backend):
    backend.store.stage(backend.key, NEW)
    backend.store.promote(backend.key)
    # Overwrite `current` with a half written one, the way a hand edit would.
    data, version = backend.store._read(backend.key)
    data["current"] = {"username": "analytics_app_b"}
    backend.store._write(backend.key, data, cas=version)

    with pytest.raises(StoreError, match="has no 'password' key"):
        backend.store.current(backend.key)
