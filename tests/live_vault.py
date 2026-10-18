"""Wiring for the tests that need a real Vault, and the trap in them.

`ROTATOR_TEST_VAULT_ADDR` and `ROTATOR_TEST_VAULT_TOKEN` point at a Vault this
suite may write to. Unset, every live test skips, which is what keeps the
default run offline and Docker free.

The trap is the same shape as the Postgres one and has a different cause. A
KV **v1** mount answers the same URLs as a v2 mount and ignores `options.cas`
entirely: the write succeeds, the version is not checked, and the concurrency
guard this store is built on is simply not there. Pointed at a v1 mount the
suite used to go green on a store that could lose a rotation. `requires_kv_v2`
asks the server which engine it is, by writing a document and looking at
whether the read comes back with metadata, and skips with a reason rather than
testing nothing.
"""

from __future__ import annotations

import os
import uuid

import pytest

from rotator.errors import StoreError
from rotator.stores.vault import UrllibTransport

ADDR_ENV = "ROTATOR_TEST_VAULT_ADDR"
TOKEN_ENV = "ROTATOR_TEST_VAULT_TOKEN"
MOUNT_ENV = "ROTATOR_TEST_VAULT_MOUNT"


def address() -> str:
    value = os.environ.get(ADDR_ENV)
    if not value:
        pytest.skip(f"{ADDR_ENV} is not set, so there is no Vault to run against")
    return value


def token() -> str:
    value = os.environ.get(TOKEN_ENV)
    if not value:
        pytest.skip(f"{TOKEN_ENV} is not set, so there is no Vault to run against")
    return value


def mount() -> str:
    """The KV v2 mount to work in. `secret` is what a dev server starts with."""
    return os.environ.get(MOUNT_ENV) or "secret"


def transport() -> UrllibTransport:
    return UrllibTransport(address(), token())


def requires_kv_v2() -> None:
    """Is the configured mount actually KV v2?

    Read, not assumed. A v2 read nests the document under `data` and the
    version under `metadata`; a v1 read at the same URL hands back the stored
    document itself. So write one and look.
    """
    probe = f"{mount()}/data/rotator-contract-probe/{uuid.uuid4().hex[:10]}"
    client = transport()
    client.request("POST", probe, {"data": {"probe": "1"}, "options": {"cas": 0}})
    try:
        payload = client.request("GET", probe, None).get("data") or {}
    finally:
        client.request("DELETE", probe.replace("/data/", "/metadata/", 1), None)
    if "metadata" not in payload:
        pytest.skip(
            f"mount {mount()!r} is not KV v2. KV v1 ignores options.cas, so every "
            "assertion about check and set would pass without checking anything"
        )


def requires_mount_capability() -> None:
    """The two tests that mount an engine of their own need a token that may."""
    name = f"rotator-cap-probe-{uuid.uuid4().hex[:8]}"
    client = transport()
    try:
        client.request("POST", f"sys/mounts/{name}", {"type": "kv", "options": {"version": "2"}})
    except StoreError as exc:
        pytest.skip(f"this token cannot mount a secrets engine: {exc}")
    client.request("DELETE", f"sys/mounts/{name}", None)


class Document:
    """One KV v2 path, deleted metadata and all on the way out.

    The path carries a uuid because this may be pointed at a shared Vault, and
    a fixed path would collide with whatever else is on it.
    """

    def __init__(self) -> None:
        self.transport = transport()
        self.path = f"rotator-contract/{uuid.uuid4().hex}"
        self.key = f"{mount()}/{self.path}"

    def seed(self, document: dict) -> None:
        self.transport.request(
            "POST", f"{mount()}/data/{self.path}", {"data": document, "options": {"cas": 0}}
        )

    def version(self) -> int:
        response = self.transport.request("GET", f"{mount()}/data/{self.path}", None)
        payload = response.get("data") or {}
        return int((payload.get("metadata") or {}).get("version", 0))

    def soft_delete(self) -> None:
        """`vault kv delete`: the latest version goes, its number stays."""
        self.transport.request("DELETE", f"{mount()}/data/{self.path}", None)

    def drop(self) -> None:
        self.transport.request("DELETE", f"{mount()}/metadata/{self.path}", None)
