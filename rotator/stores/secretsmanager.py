"""Secrets Manager, driven through its staging labels.

AWSCURRENT is what consumers read. AWSPENDING is the new credential before
anyone can see it. Promotion is one `UpdateSecretVersionStage` call, which is
why this is the store worth having: the publish step is atomic at the server,
so there is no window in which consumers can read half a rotation.
"""

from __future__ import annotations

import datetime as dt
import json
import secrets
from typing import Any

from ..errors import Refused, StoreError
from ..ports import Credential

CURRENT = "AWSCURRENT"
PENDING = "AWSPENDING"

#: The operations `rotator plan` may use. tests/test_plan_is_read_only.py
#: records what botocore actually sends and compares it against this set, so a
#: write slipped into the planning path fails a test rather than a review.
READ_ONLY_OPERATIONS = frozenset({"DescribeSecret", "GetSecretValue", "ListSecretVersionIds"})


class SecretsManagerStore:
    def __init__(self, client: Any, allowed_secret_ids: tuple[str, ...] | None = None) -> None:
        self._client = client
        self._allowed = frozenset(allowed_secret_ids) if allowed_secret_ids is not None else None

    def _check(self, secret_id: str) -> str:
        if self._allowed is not None and secret_id not in self._allowed:
            raise Refused(
                f"{secret_id!r} is not declared in targets.toml. The IAM policy would "
                f"refuse it too, with a message naming neither the secret nor the reason"
            )
        return secret_id

    def _not_found(self, exc: Exception) -> bool:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        return code in {"ResourceNotFoundException", "InvalidRequestException"}

    def _value(self, secret_id: str, stage: str) -> Credential | None:
        try:
            raw = self._client.get_secret_value(SecretId=secret_id, VersionStage=stage)
        except Exception as exc:  # botocore raises a generated class
            if self._not_found(exc):
                return None
            raise StoreError(f"get_secret_value({secret_id}, {stage}) failed: {exc}") from exc
        return _decode(raw.get("SecretString"), secret_id, stage)

    def _stages(self, secret_id: str) -> dict[str, list[str]]:
        """Version id to staging labels, or empty if the secret is not there.

        Absent reads as empty rather than raising, so `staged` and
        `current_age` answer None on a secret Terraform has not created yet,
        the same way `current` does. A tool that raises three different
        exceptions for one missing secret sends you looking for three bugs.
        """
        try:
            described = self._client.describe_secret(SecretId=secret_id)
        except Exception as exc:
            if self._not_found(exc):
                return {}
            raise StoreError(f"describe_secret({secret_id}) failed: {exc}") from exc
        return described.get("VersionIdsToStages", {})

    def _version_with(self, secret_id: str, stage: str) -> str | None:
        for version, stages in self._stages(secret_id).items():
            if stage in stages:
                return version
        return None

    # reads -------------------------------------------------------------

    def current(self, secret_id: str) -> Credential | None:
        return self._value(self._check(secret_id), CURRENT)

    def staged(self, secret_id: str) -> Credential | None:
        """The pending credential, if a run left one behind.

        A version can carry both labels for a moment, and `promote` closes that
        window by removing AWSPENDING itself. This guard is the second half of
        that fix: a pending label sitting on the version that is already current
        is not a half finished rotation, and reporting it as one would block
        every subsequent run on the target.
        """
        secret_id = self._check(secret_id)
        for labels in self._stages(secret_id).values():
            if PENDING in labels and CURRENT not in labels:
                return self._value(secret_id, PENDING)
        return None

    def current_age(self, secret_id: str, now: dt.datetime) -> dt.timedelta | None:
        """How long the live credential has been live.

        Not `describe_secret`'s LastChangedDate, which moves when a pending
        version is written and so reports a thirty day old password as new the
        moment a rotation starts. The age that matters is the creation date of
        the version carrying AWSCURRENT.
        """
        secret_id = self._check(secret_id)
        version = self._version_with(secret_id, CURRENT)
        if version is None:
            return None
        try:
            listed = self._client.list_secret_version_ids(
                SecretId=secret_id, IncludeDeprecated=True
            )
        except Exception as exc:
            raise StoreError(f"list_secret_version_ids({secret_id}) failed: {exc}") from exc
        for entry in listed.get("Versions", []):
            if entry.get("VersionId") == version:
                created = entry.get("CreatedDate")
                if created is None:
                    return None
                if created.tzinfo is None:
                    created = created.replace(tzinfo=dt.UTC)
                return now - created
        return None

    # writes ------------------------------------------------------------

    def stage(self, secret_id: str, credential: Credential) -> str:
        """Put the new credential behind AWSPENDING and return its version id.

        The request token has to be 32 to 64 characters and is the idempotency
        key, so it is generated rather than derived from the username: two runs
        against the same target are two versions, not one overwritten.
        """
        secret_id = self._check(secret_id)
        token = secrets.token_hex(24)
        try:
            response = self._client.put_secret_value(
                SecretId=secret_id,
                SecretString=json.dumps(
                    {"username": credential.username, "password": credential.password}
                ),
                VersionStages=[PENDING],
                ClientRequestToken=token,
            )
        except Exception as exc:
            raise StoreError(f"put_secret_value({secret_id}) failed: {exc}") from exc
        return str(response["VersionId"])

    def promote(self, secret_id: str) -> None:
        """Move AWSCURRENT onto the pending version, then drop AWSPENDING.

        The second call is not decoration. Moving AWSCURRENT leaves AWSPENDING
        where it was, so after a successful rotation the target still looks like
        it has a half finished one, and the next run refuses to start. The old
        current version picks up AWSPREVIOUS on the way through, which is a
        rollback target right up to the moment revoke runs.
        """
        secret_id = self._check(secret_id)
        stages = self._stages(secret_id)
        pending = next((v for v, s in stages.items() if PENDING in s), None)
        live = next((v for v, s in stages.items() if CURRENT in s), None)
        if pending is None:
            raise StoreError(f"{secret_id}: nothing is staged, so there is nothing to promote")
        if pending == live:
            return  # already promoted; the label removal below is all that is left
        try:
            self._client.update_secret_version_stage(
                SecretId=secret_id,
                VersionStage=CURRENT,
                MoveToVersionId=pending,
                RemoveFromVersionId=live,
            )
            self._client.update_secret_version_stage(
                SecretId=secret_id, VersionStage=PENDING, RemoveFromVersionId=pending
            )
        except Exception as exc:
            raise StoreError(f"promote({secret_id}) failed: {exc}") from exc

    def discard_staged(self, secret_id: str) -> None:
        secret_id = self._check(secret_id)
        pending = self._version_with(secret_id, PENDING)
        if pending is None:
            return
        try:
            self._client.update_secret_version_stage(
                SecretId=secret_id, VersionStage=PENDING, RemoveFromVersionId=pending
            )
        except Exception as exc:
            raise StoreError(f"discard_staged({secret_id}) failed: {exc}") from exc


def _decode(raw: str | None, secret_id: str, stage: str) -> Credential:
    if raw is None:
        raise StoreError(f"{secret_id} {stage} has no SecretString, only SecretBinary")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise StoreError(f"{secret_id} {stage} is not JSON") from exc
    if not isinstance(payload, dict):
        raise StoreError(f"{secret_id} {stage} is JSON but not an object")
    try:
        return Credential(username=str(payload["username"]), password=str(payload["password"]))
    except KeyError as exc:
        # The message names the missing key and never the value, because this
        # exception is on its way to a log.
        raise StoreError(f"{secret_id} {stage} has no {exc.args[0]!r} key") from None
