"""Fixtures. Nothing here reaches a network.

The AWS credentials are the strings moto expects. They are set before boto3 is
imported anywhere, because botocore resolves a region once and a session built
without one raises NoRegionError from inside a test that looks unrelated.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

os.environ.setdefault("AWS_DEFAULT_REGION", "eu-west-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")

ROOT = Path(__file__).resolve().parent.parent

CONFIG = """
[aws]
account_id = "111122223333"
region = "eu-west-1"
kms_key_arn = "arn:aws:kms:eu-west-1:111122223333:key/abc"

[defaults]
consumer_cache_seconds = 300
quiesce_seconds = 900
verify_attempts = 3
verify_delay_seconds = 5
max_age_days = 30
password_length = 40

[[target]]
name = "orders-db"
store = "secretsmanager"
secret_id = "prod/orders/app"
users = ["orders_app_a", "orders_app_b"]
schedule = "cron(15 3 ? * SUN *)"

[[target]]
name = "analytics-db"
store = "vault"
vault_mount = "kv"
vault_path = "analytics/app"
users = ["analytics_app_a", "analytics_app_b"]
schedule = "rate(30 days)"
"""


@pytest.fixture
def repo_root() -> Path:
    return ROOT


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    path = tmp_path / "targets.toml"
    path.write_text(CONFIG, encoding="utf-8")
    return path


@pytest.fixture
def config(config_file: Path) -> Any:
    from rotator.config import load

    return load(config_file)
