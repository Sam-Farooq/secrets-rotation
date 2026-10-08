"""targets.toml, parsed and argued with.

This file is the single source of truth. The IAM policy and the schedule
definitions Terraform consumes are rendered from it by scripts/render.py, so a
target added here and nowhere else still gets both.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ConfigError

#: Postgres folds an unquoted identifier to lower case and allows a great deal
#: more than this. The narrow rule is here so that a role name reaching
#: `ALTER ROLE` has been through something, whatever the adapter does with it.
IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
TARGET_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
SECRET_ID = re.compile(r"^[A-Za-z0-9/_+=.@-]{1,512}$")
SCHEDULE = re.compile(r"^(rate\([^)]+\)|cron\([^)]+\))$")
STORES = frozenset({"secretsmanager", "vault"})


@dataclass(frozen=True)
class Target:
    name: str
    store: str
    users: tuple[str, str]
    schedule: str
    max_age_days: int
    quiesce_seconds: int
    verify_attempts: int
    verify_delay_seconds: int
    password_length: int
    secret_id: str | None = None
    vault_mount: str | None = None
    vault_path: str | None = None

    def other_user(self, current: str) -> str:
        """The user this rotation will act on: the one nobody is using."""
        if current not in self.users:
            raise ConfigError(
                f"{self.name}: the live credential is for {current!r}, "
                f"which is not one of the declared users {self.users}"
            )
        return self.users[1] if current == self.users[0] else self.users[0]

    @property
    def key(self) -> str:
        """What the store is addressed by, whichever store it is."""
        if self.store == "secretsmanager":
            assert self.secret_id is not None
            return self.secret_id
        return f"{self.vault_mount}/{self.vault_path}"


@dataclass(frozen=True)
class AwsSettings:
    account_id: str
    region: str
    kms_key_arn: str

    def secret_arn(self, secret_id: str) -> str:
        """The ARN pattern for a secret addressed by name.

        Secrets Manager appends six random characters to the ARN of every
        secret, so a policy written by hand cannot name the ARN exactly. The
        documented answer is six single character wildcards, and the reason to
        prefer them over a trailing `*` is that `prod/orders/app*` also matches
        `prod/orders/app-replica`, which is a different secret this role has no
        business reading.
        """
        return f"arn:aws:secretsmanager:{self.region}:{self.account_id}:secret:{secret_id}-??????"


@dataclass(frozen=True)
class Config:
    aws: AwsSettings
    consumer_cache_seconds: int
    targets: tuple[Target, ...]

    def target(self, name: str) -> Target:
        for candidate in self.targets:
            if candidate.name == name:
                return candidate
        known = ", ".join(t.name for t in self.targets)
        raise ConfigError(f"no target named {name!r}. Declared: {known}")

    @property
    def secret_ids(self) -> tuple[str, ...]:
        """The allowlist. Anything outside it is refused before a call is made."""
        return tuple(
            sorted(t.secret_id for t in self.targets if t.store == "secretsmanager" and t.secret_id)
        )


def _require(mapping: dict[str, Any], field: str, where: str) -> Any:
    if field not in mapping:
        raise ConfigError(f"{where}: {field} is required")
    return mapping[field]


def _positive_int(value: Any, field: str, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConfigError(f"{where}: {field} must be a positive integer, got {value!r}")
    return value


def _target(raw: dict[str, Any], defaults: dict[str, Any], index: int) -> Target:
    where = f"target[{index}]"
    name = _require(raw, "name", where)
    if not isinstance(name, str) or not TARGET_NAME.match(name):
        raise ConfigError(f"{where}: name {name!r} must match {TARGET_NAME.pattern}")
    where = f"target {name!r}"

    store = _require(raw, "store", where)
    if store not in STORES:
        raise ConfigError(f"{where}: store must be one of {sorted(STORES)}, got {store!r}")

    users = _require(raw, "users", where)
    if not isinstance(users, list) or len(users) != 2:
        raise ConfigError(
            f"{where}: users must be exactly two role names. The two user pattern "
            f"needs somewhere to put the new password that nobody is using"
        )
    if users[0] == users[1]:
        raise ConfigError(f"{where}: the two users must differ, both are {users[0]!r}")
    for user in users:
        if not isinstance(user, str) or not IDENTIFIER.match(user):
            raise ConfigError(f"{where}: user {user!r} must match {IDENTIFIER.pattern}")

    schedule = _require(raw, "schedule", where)
    if not isinstance(schedule, str) or not SCHEDULE.match(schedule):
        raise ConfigError(
            f"{where}: schedule {schedule!r} must be an EventBridge Scheduler "
            f"expression, rate(...) or cron(...)"
        )

    secret_id = raw.get("secret_id")
    vault_mount = raw.get("vault_mount")
    vault_path = raw.get("vault_path")
    if store == "secretsmanager":
        if not isinstance(secret_id, str) or not SECRET_ID.match(secret_id):
            raise ConfigError(f"{where}: secret_id {secret_id!r} is required and must be a name")
        if vault_mount or vault_path:
            raise ConfigError(f"{where}: a secretsmanager target has no vault_mount or vault_path")
    else:
        if not isinstance(vault_mount, str) or not isinstance(vault_path, str):
            raise ConfigError(f"{where}: a vault target needs vault_mount and vault_path")
        if secret_id:
            raise ConfigError(
                f"{where}: a vault target has no secret_id. It would end up in the "
                f"IAM policy as a secret this role may read, which it is not"
            )

    merged = {**defaults, **raw}
    numbers = {
        field: _positive_int(_require(merged, field, where), field, where)
        for field in (
            "max_age_days",
            "quiesce_seconds",
            "verify_attempts",
            "verify_delay_seconds",
            "password_length",
        )
    }
    if numbers["password_length"] < 24:
        raise ConfigError(f"{where}: password_length {numbers['password_length']} is below 24")

    return Target(
        name=name,
        store=store,
        users=(users[0], users[1]),
        schedule=schedule,
        secret_id=secret_id,
        vault_mount=vault_mount,
        vault_path=vault_path,
        **numbers,
    )


def load(path: str | Path) -> Config:
    path = Path(path)
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"no config at {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from exc

    aws_raw = _require(raw, "aws", str(path))
    aws = AwsSettings(
        account_id=str(_require(aws_raw, "account_id", "[aws]")),
        region=str(_require(aws_raw, "region", "[aws]")),
        kms_key_arn=str(_require(aws_raw, "kms_key_arn", "[aws]")),
    )
    if not re.fullmatch(r"\d{12}", aws.account_id):
        raise ConfigError(f"[aws]: account_id {aws.account_id!r} is not twelve digits")

    defaults = raw.get("defaults", {})
    consumer_cache_seconds = _positive_int(
        _require(defaults, "consumer_cache_seconds", "[defaults]"),
        "consumer_cache_seconds",
        "[defaults]",
    )

    targets = tuple(
        _target(entry, defaults, index) for index, entry in enumerate(raw.get("target", []))
    )
    if not targets:
        raise ConfigError(f"{path} declares no targets")

    names = [t.name for t in targets]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise ConfigError(f"duplicate target names: {duplicates}")

    # The whole point of the quiesce window is to outlast the longest cache a
    # consumer keeps the credential in. A window shorter than that TTL revokes
    # a password some process is still holding, which is the outage this tool
    # exists to avoid, so it is a config error rather than a runtime surprise.
    for target in targets:
        if target.quiesce_seconds <= consumer_cache_seconds:
            raise ConfigError(
                f"target {target.name!r}: quiesce_seconds {target.quiesce_seconds} is not "
                f"longer than consumer_cache_seconds {consumer_cache_seconds}. Revoking "
                f"inside the cache window is the outage this tool exists to avoid"
            )

    return Config(aws=aws, consumer_cache_seconds=consumer_cache_seconds, targets=targets)
