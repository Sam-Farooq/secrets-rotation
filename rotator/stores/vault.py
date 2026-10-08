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


class VaultTransport(Protocol):
    """One method, so the tests can replace Vault with a dict."""

    def request(self, method: str, path: str, body: dict[str, Any] | None) -> dict[str, Any]: ...


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
            if exc.code == 404:
                return {}
            # Vault puts the reason in the body. Without reading it the error is
            # "HTTP Error 400: Bad Request", which does not say check and set.
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise StoreError(f"vault {method} {path} returned {exc.code}: {detail}") from exc
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
        data = payload.get("data") or {}
        version = int((payload.get("metadata") or {}).get("version", 0))
        return dict(data), version

    def _write(self, key: str, data: dict[str, Any], cas: int) -> None:
        mount, path = self._split(key)
        quoted = urllib.parse.quote(path)
        self._transport.request(
            "POST", f"{mount}/data/{quoted}", {"data": data, "options": {"cas": cas}}
        )

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
        self._write(key, data, cas=version)
        return str(version + 1)

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
