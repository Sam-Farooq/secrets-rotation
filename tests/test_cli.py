"""The commands, through main(), with boto3 pointed at moto."""

from __future__ import annotations

import pytest
from fakes import FakeClock

from rotator import __version__
from rotator.cli import main
from rotator.passwords import ALPHABET, generate


def run(argv, config_file, clock=None):
    return main([*argv], clock=clock or FakeClock())


def test_plan_reports_every_target_and_changes_nothing(
    config_file, secretsmanager, seeded_secret, capsys
):
    code = run(["--config", str(config_file), "plan", "--target", "orders-db"], config_file)

    out = capsys.readouterr().out
    assert code == 0
    assert "orders-db" in out
    assert "orders_app_b" in out
    assert "of 30d" in out


def test_plan_exits_nonzero_when_something_is_blocked(
    config_file, secretsmanager, seeded_secret, capsys
):
    from rotator.config import load
    from rotator.ports import Credential
    from rotator.stores import SecretsManagerStore

    config = load(config_file)
    SecretsManagerStore(secretsmanager, allowed_secret_ids=config.secret_ids).stage(
        seeded_secret, Credential("orders_app_b", "half-finished")
    )

    code = run(["--config", str(config_file), "plan", "--target", "orders-db"], config_file)

    assert code == 1
    assert "blocked:" in capsys.readouterr().out


def test_status_reads_both_labels(config_file, secretsmanager, seeded_secret, capsys):
    code = run(["--config", str(config_file), "status", "--target", "orders-db"], config_file)

    out = capsys.readouterr().out
    assert code == 0
    assert "current orders_app_a" in out
    assert "staged none" in out


def test_rotate_without_confirm_refuses_and_says_what_to_run(config_file, capsys):
    code = run(["--config", str(config_file), "rotate", "--target", "orders-db"], config_file)

    assert code == 2
    assert "Pass --confirm" in capsys.readouterr().err


def test_discard_clears_what_a_stopped_run_left(config_file, secretsmanager, seeded_secret, capsys):
    from rotator.config import load
    from rotator.ports import Credential
    from rotator.stores import SecretsManagerStore

    config = load(config_file)
    store = SecretsManagerStore(secretsmanager, allowed_secret_ids=config.secret_ids)
    store.stage(seeded_secret, Credential("orders_app_b", "half-finished"))

    code = run(["--config", str(config_file), "discard", "orders-db"], config_file)

    assert code == 0
    assert "discarded the staged credential for orders_app_b" in capsys.readouterr().out
    assert store.staged(seeded_secret) is None


def test_discard_with_nothing_staged_is_not_an_error(
    config_file, secretsmanager, seeded_secret, capsys
):
    code = run(["--config", str(config_file), "discard", "orders-db"], config_file)

    assert code == 0
    assert "nothing staged" in capsys.readouterr().out


def test_an_unknown_target_lists_the_known_ones(config_file, capsys):
    code = run(["--config", str(config_file), "plan", "--target", "nope"], config_file)

    assert code == 2
    assert "no target named 'nope'" in capsys.readouterr().err


def test_a_vault_target_without_the_two_env_vars_says_which(config_file, monkeypatch, capsys):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)

    code = run(["--config", str(config_file), "plan", "--target", "analytics-db"], config_file)

    assert code == 2
    assert "VAULT_ADDR and VAULT_TOKEN" in capsys.readouterr().err


def test_a_broken_config_is_reported_rather_than_traced(tmp_path, capsys):
    path = tmp_path / "targets.toml"
    path.write_text("this is not toml = = =", encoding="utf-8")

    code = main(["--config", str(path), "plan"], clock=FakeClock())

    assert code == 2
    assert "not valid TOML" in capsys.readouterr().err


def test_version_is_the_package_version(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["--version"])

    assert caught.value.code == 0
    assert capsys.readouterr().out.strip() == __version__


def test_no_subcommand_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as caught:
        main([])

    assert caught.value.code == 2


def test_a_generated_password_uses_only_characters_every_consumer_survives():
    password = generate(40)

    assert len(password) == 40
    assert set(password) <= set(ALPHABET)
    for forbidden in ("/", "@", '"', "'", " ", ":", "\\", "`"):
        assert forbidden not in ALPHABET


def test_two_generated_passwords_differ():
    assert generate(40) != generate(40)


def test_a_password_below_the_floor_is_refused():
    with pytest.raises(ValueError, match="below 24"):
        generate(16)
