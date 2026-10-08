"""What targets.toml refuses to say."""

from __future__ import annotations

import pytest

from rotator.config import load
from rotator.errors import ConfigError

BASE = """
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
"""


def write(tmp_path, text):
    path = tmp_path / "targets.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_the_committed_file_loads(repo_root):
    config = load(repo_root / "targets.toml")

    assert [target.name for target in config.targets] == [
        "orders-db",
        "reporting-db",
        "analytics-db",
    ]
    assert config.secret_ids == ("prod/orders/app", "prod/reporting/app")


def test_defaults_fill_in_and_a_target_overrides_them(repo_root):
    config = load(repo_root / "targets.toml")

    assert config.target("orders-db").quiesce_seconds == 900
    assert config.target("reporting-db").quiesce_seconds == 3600
    assert config.target("reporting-db").max_age_days == 14


def test_a_quiesce_window_inside_the_cache_ttl_is_refused(tmp_path):
    text = BASE.replace("quiesce_seconds = 900", "quiesce_seconds = 120")

    with pytest.raises(ConfigError) as caught:
        load(write(tmp_path, text))

    assert "is not longer than consumer_cache_seconds" in str(caught.value)


def test_one_user_is_not_a_two_user_pattern(tmp_path):
    text = BASE.replace('users = ["orders_app_a", "orders_app_b"]', 'users = ["orders_app_a"]')

    with pytest.raises(ConfigError, match="exactly two role names"):
        load(write(tmp_path, text))


def test_the_same_user_twice_is_refused(tmp_path):
    text = BASE.replace(
        'users = ["orders_app_a", "orders_app_b"]', 'users = ["orders_app_a", "orders_app_a"]'
    )

    with pytest.raises(ConfigError, match="the two users must differ"):
        load(write(tmp_path, text))


def test_a_role_name_sql_would_need_quoting_for_is_refused(tmp_path):
    text = BASE.replace(
        'users = ["orders_app_a", "orders_app_b"]', 'users = ["orders app a", "orders_app_b"]'
    )

    with pytest.raises(ConfigError, match="must match"):
        load(write(tmp_path, text))


def test_a_vault_target_with_a_secret_id_is_refused(tmp_path):
    text = (
        BASE
        + """
[[target]]
name = "analytics-db"
store = "vault"
vault_mount = "kv"
vault_path = "analytics/app"
secret_id = "prod/analytics/app"
users = ["analytics_app_a", "analytics_app_b"]
schedule = "rate(30 days)"
"""
    )

    with pytest.raises(ConfigError) as caught:
        load(write(tmp_path, text))

    assert "would end up in the IAM policy" in str(caught.value)


def test_a_schedule_that_is_not_an_eventbridge_expression_is_refused(tmp_path):
    text = BASE.replace('schedule = "cron(15 3 ? * SUN *)"', 'schedule = "0 3 * * 0"')

    with pytest.raises(ConfigError, match="rate\\(...\\) or cron\\(...\\)"):
        load(write(tmp_path, text))


def test_a_short_password_length_is_refused(tmp_path):
    text = BASE.replace("password_length = 40", "password_length = 12")

    with pytest.raises(ConfigError, match="is below 24"):
        load(write(tmp_path, text))


def test_an_account_id_that_is_not_twelve_digits_is_refused(tmp_path):
    text = BASE.replace('account_id = "111122223333"', 'account_id = "1234"')

    with pytest.raises(ConfigError, match="not twelve digits"):
        load(write(tmp_path, text))


def test_duplicate_target_names_are_refused(tmp_path):
    text = BASE + BASE[BASE.index("[[target]]") :]

    with pytest.raises(ConfigError, match="duplicate target names"):
        load(write(tmp_path, text))


def test_a_file_with_no_targets_is_refused(tmp_path):
    text = BASE.split("[[target]]")[0]

    with pytest.raises(ConfigError, match="declares no targets"):
        load(write(tmp_path, text))


def test_a_missing_file_says_where_it_looked(tmp_path):
    with pytest.raises(ConfigError, match="no config at"):
        load(tmp_path / "absent.toml")


def test_other_user_rejects_a_username_it_does_not_know(repo_root):
    target = load(repo_root / "targets.toml").target("orders-db")

    assert target.other_user("orders_app_a") == "orders_app_b"
    assert target.other_user("orders_app_b") == "orders_app_a"
    with pytest.raises(ConfigError, match="not one of the declared users"):
        target.other_user("postgres")


def test_a_vault_target_is_keyed_by_mount_and_path(repo_root):
    config = load(repo_root / "targets.toml")

    assert config.target("analytics-db").key == "kv/analytics/app"
    assert config.target("orders-db").key == "prod/orders/app"
