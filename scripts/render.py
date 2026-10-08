#!/usr/bin/env python3
"""Render targets.toml into the two files Terraform reads.

    python3 scripts/render.py              write them
    python3 scripts/render.py --check      fail if the committed ones are stale

CI runs --check, which is the only thing keeping the IAM policy honest: a
target added to targets.toml without re-rendering would get a schedule from
nowhere and no permission to touch its secret.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rotator.config import load  # noqa: E402
from rotator.errors import RotatorError  # noqa: E402
from rotator.iam import render, rotation_policy, schedule_inputs  # noqa: E402

OUTPUTS = (
    ("rotation_policy.json", rotation_policy),
    ("targets.json", schedule_inputs),
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(ROOT / "targets.toml"))
    parser.add_argument("--out", default=str(ROOT / "terraform" / "generated"))
    parser.add_argument("--check", action="store_true", help="compare instead of writing")
    args = parser.parse_args(argv)

    try:
        config = load(args.config)
    except RotatorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stale = []
    for filename, builder in OUTPUTS:
        wanted = render(builder(config))
        path = out / filename
        if args.check:
            found = path.read_text(encoding="utf-8") if path.exists() else ""
            if found != wanted:
                stale.append(filename)
            continue
        path.write_text(wanted, encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")

    if stale:
        print(
            "stale, run scripts/render.py: " + ", ".join(stale),
            file=sys.stderr,
        )
        return 1
    if args.check:
        print("terraform/generated is current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
