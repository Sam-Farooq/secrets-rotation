"""One JSON line per transition.

A rotation that stops halfway leaves a database and a secret store in states
that have to be read together to make sense. This file is what makes that
readable afterwards: the last line for a target names the state it stopped in,
and docs/runbooks keys off exactly those names.

What is never written here: a password, and anything derived from one.
tests/test_audit.py asserts that over a full run.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any, Protocol

from .machine import Step


class Audit(Protocol):
    def record(self, target: str, step: Step, at: dt.datetime, **extra: Any) -> None: ...


class NullAudit:
    def record(self, target: str, step: Step, at: dt.datetime, **extra: Any) -> None:
        return None


class MemoryAudit:
    def __init__(self) -> None:
        self.lines: list[dict[str, Any]] = []

    def record(self, target: str, step: Step, at: dt.datetime, **extra: Any) -> None:
        self.lines.append(_line(target, step, at, extra))


class FileAudit:
    """Appends to a file, opening it per line.

    Per line rather than holding a handle because the process is a scheduled
    task that can be killed between steps, and a buffered handle loses the one
    line that says where it got to.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def record(self, target: str, step: Step, at: dt.datetime, **extra: Any) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(_line(target, step, at, extra), sort_keys=True) + "\n")


def _line(target: str, step: Step, at: dt.datetime, extra: dict[str, Any]) -> dict[str, Any]:
    line = {
        "at": at.isoformat(),
        "target": target,
        "from": str(step.frm),
        "event": str(step.event),
        "to": str(step.to),
    }
    if step.detail:
        line["detail"] = step.detail
    for key, value in extra.items():
        line[key] = value
    return line
