"""Facts about a real Vault that no fake can produce.

The contract suite says the fake and the server agree. This file is the other
half: the things only a server knows, chiefly what the KV v2 engine does that
the issue asking for this tier assumed it did something else about.

All of it is marked `live_vault` and skips without ROTATOR_TEST_VAULT_ADDR.
"""

from __future__ import annotations

import uuid

import live_vault as live
import pytest
from fakes import FakeClock

from rotator.errors import StoreError
from rotator.ports import Credential
from rotator.stores import VaultKvStore

pytestmark = pytest.mark.live_vault

FIRST = Credential("analytics_app_a", "the-old-one")
SECOND = Credential("analytics_app_b", "a-new-password")


@pytest.fixture
def document():
    live.requires_kv_v2()
    made = live.Document()
    yield made
    made.drop()


@pytest.fixture
def store(document):
    return VaultKvStore(live.transport(), clock=FakeClock())


def test_a_kv_v2_read_carries_no_lease_to_revoke(document, store):
    """The issue that asked for this tier asked about lease revocation. There
    are no leases here, and that is the answer rather than a gap.

    A KV v2 read comes back with an empty `lease_id`, a duration of zero and
    `renewable: false`, because a static secret is not a dynamic one: Vault is
    not holding a credential it can withdraw. So nothing Vault does limits how
    long a retired password stays usable. The only thing that does is how long
    a consumer caches it, which is why `consumer_cache_seconds` exists and why
    the quiesce window is derived from it rather than from anything Vault says.
    """
    store.stage(document.key, FIRST)
    envelope = document.transport.request("GET", f"{live.mount()}/data/{document.path}", None)

    assert envelope["lease_id"] == ""
    assert envelope["lease_duration"] == 0
    assert envelope["renewable"] is False


def test_the_server_is_the_one_refusing_a_stale_check_and_set(document, store):
    """The contract test drives the race through this tool's own transport.

    This one sends a stale `cas` straight at Vault, so the 400 is the server's
    and not a rule enforced on the way out. The distinction is the same one
    the Postgres tier draws between implementing SCRAM and implementing the
    SCRAM that particular server accepts.
    """
    store.stage(document.key, FIRST)
    stale = 0

    with pytest.raises(StoreError, match="check-and-set parameter did not match"):
        document.transport.request(
            "POST",
            f"{live.mount()}/data/{document.path}",
            {"data": {"current": {"username": "x", "password": "y"}}, "options": {"cas": stale}},
        )


def test_a_read_straight_after_a_write_sees_it(document, store):
    """The quiesce window is for consumer caches, not for Vault.

    The issue asked what a read returns between a write and its replication.
    On the single node this runs against, the answer is: the value just
    written, with no window at all. That is worth pinning because it says the
    window the rotator waits out is the consumers' and not the store's.

    What this does not prove: a performance replica may lag, and nothing here
    runs one. The claim in the README is scoped to a single node for that
    reason.
    """
    store.stage(document.key, SECOND)

    assert store.staged(document.key) == SECOND


def test_the_version_before_a_promote_is_still_readable(document, store):
    """Worth knowing before a runbook needs it.

    KV v2 keeps the previous versions, so a promote that published the wrong
    credential can be read back rather than reconstructed. `stopped-after-
    promote.md` sends the operator to the `previous` field this tool writes;
    the engine holds the whole prior document as well.
    """
    store.stage(document.key, FIRST)
    store.promote(document.key)
    before_second = document.version()
    store.stage(document.key, SECOND)
    store.promote(document.key)

    older = document.transport.request(
        "GET", f"{live.mount()}/data/{document.path}?version={before_second}", None
    )

    assert older["data"]["data"]["current"]["username"] == FIRST.username
    assert store.current(document.key) == SECOND


def test_a_kv_v1_mount_is_refused_rather_than_quietly_dropping_check_and_set(document):
    """The trap this tier exists to catch, driven rather than described.

    A KV v1 mount answers the same URLs. It stores `options.cas` as ordinary
    data and ignores it, so every write succeeds whatever version it claims to
    have read, and the guard the whole two phase design rests on is not there.
    Measured: before the store checked, a stage against a v1 mount returned a
    version number and the stale write that followed it went through.
    """
    live.requires_mount_capability()
    name = f"rotator-v1-{uuid.uuid4().hex[:8]}"
    client = live.transport()
    client.request("POST", f"sys/mounts/{name}", {"type": "kv", "options": {"version": "1"}})
    try:
        v1_store = VaultKvStore(client, clock=FakeClock())
        with pytest.raises(StoreError, match="does not answer like KV v2"):
            v1_store.stage(f"{name}/analytics/app", FIRST)
    finally:
        client.request("DELETE", f"sys/mounts/{name}", None)


def test_a_token_without_the_policy_gets_an_error_not_an_absent_secret(document, store):
    """A denial has to stop the rotation, not look like an empty path.

    403 was already handled. It is asserted here because it sits one branch
    away from the 404 that this tier changed, and an edit that widened the
    404 case to every error would read a permission failure as "nothing has
    been rotated yet" and stage a credential nobody can read.
    """
    live.requires_mount_capability()
    store.stage(document.key, FIRST)
    client = live.transport()
    policy = f"rotator-narrow-{uuid.uuid4().hex[:8]}"
    client.request(
        "PUT",
        f"sys/policy/{policy}",
        {"policy": 'path "secret/data/nothing-at-all/*" { capabilities = ["read"] }'},
    )
    try:
        issued = client.request("POST", "auth/token/create", {"policies": [policy], "ttl": "5m"})
        narrow = VaultKvStore(
            type(client)(live.address(), issued["auth"]["client_token"]), clock=FakeClock()
        )
        with pytest.raises(StoreError, match="permission denied"):
            narrow.current(document.key)
    finally:
        client.request("DELETE", f"sys/policy/{policy}", None)
