"""Four subcommands. Three of them change nothing.

    plan      what would rotate, and what is in the way
    status    where each target is, read back from its store
    rotate    do it
    discard   drop a staged credential a stopped run left behind

`rotate` is the only one that writes, and it still refuses without --confirm,
because the thing that invokes it is a scheduled task and the thing that reads
this help is a person at 2am.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from . import __version__
from .audit import FileAudit, NullAudit
from .config import Config, Target, load
from .database import PostgresAdmin
from .errors import ConfigError, RotatorError
from .ports import Clock, SecretStore, SystemClock
from .rotation import Rotation, plan
from .stores import SecretsManagerStore, UrllibTransport, VaultKvStore


def _store(target: Target, config: Config, clock: Clock) -> SecretStore:
    if target.store == "secretsmanager":
        import boto3  # imported here so plan on a vault target needs no boto3

        client = boto3.client("secretsmanager", region_name=config.aws.region)
        return SecretsManagerStore(client, allowed_secret_ids=config.secret_ids)

    import os

    address = os.environ.get("VAULT_ADDR")
    token = os.environ.get("VAULT_TOKEN")
    if not address or not token:
        raise ConfigError(
            f"target {target.name!r} reads from Vault, so VAULT_ADDR and VAULT_TOKEN "
            f"have to be set. Neither is read from targets.toml on purpose"
        )
    return VaultKvStore(UrllibTransport(address, token), clock=clock)


def _targets(config: Config, chosen: str | None) -> tuple[Target, ...]:
    return (config.target(chosen),) if chosen else config.targets


def _plan(args: argparse.Namespace, config: Config, clock: Clock) -> int:
    now = clock.now()
    rows = [
        plan(target, _store(target, config, clock), now) for target in _targets(config, args.target)
    ]
    width = max(len(row.target) for row in rows)
    for row in rows:
        age = "unknown" if row.age_days is None else f"{row.age_days:.2f}d"
        nxt = row.next_username or "-"
        print(
            f"{row.target:<{width}}  {row.verdict:<7}  age {age:>9}"
            f"  of {row.max_age_days}d  -> {nxt}"
        )
        for blocker in row.blockers:
            print(f"{'':<{width}}  blocked: {blocker}")
    return 1 if any(row.blockers for row in rows) else 0


def _status(args: argparse.Namespace, config: Config, clock: Clock) -> int:
    for target in _targets(config, args.target):
        store = _store(target, config, clock)
        live = store.current(target.key)
        staged = store.staged(target.key)
        print(
            f"{target.name}: current {live.username if live else 'none'}, "
            f"staged {staged.username if staged else 'none'}, "
            f"users {target.users[0]}/{target.users[1]}"
        )
    return 0


def _rotate(args: argparse.Namespace, config: Config, clock: Clock) -> int:
    if not args.confirm:
        print(
            "rotate revokes a credential. Pass --confirm, or run plan first.",
            file=sys.stderr,
        )
        return 2
    audit: Any = FileAudit(args.audit) if args.audit else NullAudit()
    admin = PostgresAdmin(
        admin_dsn=_required_env("ROTATOR_ADMIN_DSN"),
        verify_dsn_template=_required_env("ROTATOR_VERIFY_DSN"),
    )
    worst = 0
    for target in _targets(config, args.target):
        outcome = Rotation(
            target=target,
            store=_store(target, config, clock),
            admin=admin,
            clock=clock,
            audit=audit,
        ).run()
        print(outcome.summary())
        if outcome.needs_a_human:
            print(
                f"  read docs/runbooks/stopped-after-promote.md. {target.name} is serving "
                f"the new credential and the old one is still alive.",
                file=sys.stderr,
            )
            worst = max(worst, 3)
        elif not outcome.ok:
            worst = max(worst, 1)
    return worst


def _discard(args: argparse.Namespace, config: Config, clock: Clock) -> int:
    target = config.target(args.target)
    store = _store(target, config, clock)
    staged = store.staged(target.key)
    if staged is None:
        print(f"{target.name}: nothing staged")
        return 0
    store.discard_staged(target.key)
    print(f"{target.name}: discarded the staged credential for {staged.username}")
    return 0


def _required_env(name: str) -> str:
    import os

    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"{name} is not set")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rotator",
        description=__doc__,
        # The description is a table. The default formatter reflows it
        # into a paragraph, which is how this got noticed.
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", default="targets.toml", help="path to targets.toml")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, handler, helptext in (
        ("plan", _plan, "report what would rotate, changing nothing"),
        ("status", _status, "where each target is, read back from its store"),
    ):
        child = sub.add_parser(name, help=helptext)
        child.add_argument("--target", help="one target by name, default all")
        child.set_defaults(handler=handler)

    rotate = sub.add_parser("rotate", help="rotate, two phase, verify before revoke")
    rotate.add_argument("--target", help="one target by name, default all")
    rotate.add_argument("--confirm", action="store_true", help="required; this one writes")
    rotate.add_argument("--audit", help="append the transition log to this file")
    rotate.set_defaults(handler=_rotate)

    discard = sub.add_parser("discard", help="drop a staged credential left by a stopped run")
    discard.add_argument("target", help="target name")
    discard.set_defaults(handler=_discard)
    return parser


def main(argv: list[str] | None = None, clock: Clock | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load(args.config)
        return int(args.handler(args, config, clock or SystemClock()))
    except RotatorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
