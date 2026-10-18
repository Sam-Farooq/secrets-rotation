"""Vault KV v2, which has no staging labels.

Secrets Manager hands the publish step to the server. Vault does not: a KV v2
secret has versions, and a version is a whole document, not a label you can
move. So the pending credential lives in a field of the same document and
promotion is a write that moves it from one field to another.

That sounds worse and is not, because KV v2 has check and set. Every write here
sends `options.cas` with the version it read, so a second rotator running
against the same path gets a 400 instead of silently overwriting the first
one's work. The atomicity Secrets Manager gets from the label move, this gets
from the version number.

Reached through urllib rather than hvac. Two endpoints are used, both are a
GET and a POST of JSON, and hvac is a dependency with its own release cadence
and its own opinions about retries.

Three of the refusals below were written after this ran against a real Vault
for the first time, and none of them is guessable from the HTTP status alone.
They are the ones that stop a misconfiguration reading as an empty secret.
"""

from __future__ import annotations

import datetime as dt
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Protocol

from ..errors import StoreError
from ..ports import Clock, Credential, SystemClock

NOT_KV_V2 = (
    "{key}: mount {mount!r} does not answer like KV v2. On KV v1 `options.cas` "
    "is stored as ordinary data and ignored, so the check and set this store "
    "relies on would do nothing and two rotators would overwrite each other."
)


class VaultTransport(Protocol):
    """One method, so the tests can replace Vault with a dict."""

    def request(self, method: str, path: str, body: dict[str, Any] | None) -> dict[str, Any]: ...


def not_found(method: str, path: str, detail: str) -> dict[str, Any]:
    """What a 404 means, which is three different things.

    A secret that is not there answers with an empty `errors` list, and that
    one really is absent. A **mount** that is not there answers with `no
    handler for route`, and reading that as "no secret here" turns a typo in
    `vault_mount` into a plan that reports the target has never been rotated.
    A version that has been **soft deleted** answers 404 and still carries its
    metadata, and the version number in it is the one the next write has to
    send as `cas`.

    So the body is parsed rather than discarded. Throwing it away cost the
    third case a correct error message: the write that followed sent `cas: 0`
    against a path whose version was 2, and the operator was told another
    rotator was writing to the path.
    """
    try:
        payload = dict(json.loads(detail))
    except ValueError:
        payload = {}
    errors = payload.get("errors")
    if errors:
        reason = "; ".join(str(error) for error in errors)
        raise StoreError(f"vault {method} {path} returned 404: {reason[:500]}")
    return payload


class UrllibTransport:
    def __init__(self, address: str, token: str, timeout: float = 10.0) -> None:
        self._address = address.rstrip("/")
        self._token = token
        self._timeout = timeout

    def request(self, method: str, path: str, body: dict[str, Any] | None) -> dict[str, Any]:
        url = f"{self._address}/v1/{path.lstrip('/')}"
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("X-Vault-Token", self._token)
        request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            # Vault puts the reason in the body. Without reading it the error is
            # "HTTP Error 400: Bad Request", which does not say check and set.
            detail = exc.read().decode("utf-8", "replace")
            if exc.code == 404:
                return not_found(method, path, detail)
            raise StoreError(f"vault {method} {path} returned {exc.code}: {detail[:500]}") from exc
        except urllib.error.URLError as exc:
            raise StoreError(f"vault {method} {path} did not connect: {exc.reason}") from exc
        if not raw:
            return {}
        return dict(json.loads(raw))


class VaultKvStore:
    """A KV v2 document holding `current`, optionally `pending`, and the time
    the rotator last promoted one into the other."""

    def __init__(self, transport: VaultTransport, clock: Clock | None = None) -> None:
        self._transport = transport
        self._clock = clock or SystemClock()

    @staticmethod
    def _split(key: str) -> tuple[str, str]:
        mount, _, path = key.partition("/")
        if not mount or not path:
            raise StoreError(f"{key!r} is not <mount>/<path>")
        return mount, path

    def _read(self, key: str) -> tuple[dict[str, Any], int]:
        mount, path = self._split(key)
        quoted = urllib.parse.quote(path)
        response = self._transport.request("GET", f"{mount}/data/{quoted}", None)
        payload = response.get("data") or {}
        # A KV v2 read nests the document under `data` and the version under
        # `metadata`. A KV v1 read at the same URL returns the stored document
        # itself, so the absence of `metadata` on a document that exists is the
        # mount telling you which engine it is. Asking `sys/mounts` instead
        # would be a round trip and a capability the rotator's token should not
        # need.
        if payload and "metadata" not in payload:
            raise StoreError(NOT_KV_V2.format(key=key, mount=mount))
        data = payload.get("data") or {}
        version = int((payload.get("metadata") or {}).get("version", 0))
        return dict(data), version

    def _write(self, key: str, data: dict[str, Any], cas: int) -> int:
        """Write, and return the version the server says it created.

        A KV v2 write answers with the new version. A KV v1 write answers 204
        with no body, which is the second place the wrong engine shows up. It
        is caught after the fact rather than before, because on a path that has
        never been written there is nothing to read the engine from, and an
        error naming the mount beats a rotation that believes in a check and
        set nobody performed.
        """
        mount, path = self._split(key)
        quoted = urllib.parse.quote(path)
        response = self._transport.request(
            "POST", f"{mount}/data/{quoted}", {"data": data, "options": {"cas": cas}}
        )
        version = (response.get("data") or {}).get("version")
        if version is None:
            raise StoreError(NOT_KV_V2.format(key=key, mount=mount))
        return int(version)

    @staticmethod
    def _credential(blob: Any, key: str, field: str) -> Credential | None:
        if not isinstance(blob, dict):
            return None
        try:
            return Credential(username=str(blob["username"]), password=str(blob["password"]))
        except KeyError as exc:
            raise StoreError(f"{key} {field} has no {exc.args[0]!r} key") from None

    def current(self, key: str) -> Credential | None:
        data, _ = self._read(key)
        return self._credential(data.get("current"), key, "current")

    def staged(self, key: str) -> Credential | None:
        data, _ = self._read(key)
        return self._credential(data.get("pending"), key, "pending")

    def current_age(self, key: str, now: dt.datetime) -> dt.timedelta | None:
        """Read from `rotated_at`, a field this tool writes itself.

        KV v2 metadata has a created_time per version, and it moves on every
        write including the one that stages a pending value, so it answers a
        different question. A secret seeded by hand has no `rotated_at` at all,
        and the plan reports that as a blocker rather than guessing an age.
        """
        data, _ = self._read(key)
        stamp = data.get("rotated_at")
        if not isinstance(stamp, str):
            return None
        try:
            parsed = dt.datetime.fromisoformat(stamp)
        except ValueError as exc:
            raise StoreError(f"{key} rotated_at {stamp!r} is not an ISO timestamp") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.UTC)
        return now - parsed

    def stage(self, key: str, credential: Credential) -> str:
        data, version = self._read(key)
        data["pending"] = {"username": credential.username, "password": credential.password}
        # The version the server reports, not `version + 1`. They agree on a
        # healthy path and the server is the one that knows.
        return str(self._write(key, data, cas=version))

    def promote(self, key: str) -> None:
        data, version = self._read(key)
        pending = data.get("pending")
        if not isinstance(pending, dict):
            raise StoreError(f"{key}: nothing is staged, so there is nothing to promote")
        promoted = {
            "current": pending,
            "previous": data.get("current"),
            "rotated_at": self._clock.now().isoformat(),
        }
        self._write(key, promoted, cas=version)

    def discard_staged(self, key: str) -> None:
        data, version = self._read(key)
        if "pending" not in data:
            return
        data.pop("pending")
        self._write(key, data, cas=version)
