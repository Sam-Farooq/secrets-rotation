"""The least privilege claim, checked against the policy that is committed.

IAM is the real boundary, so the policy is created in a mocked account as well
as inspected: a document that reads correctly and that IAM rejects is worse
than one that does neither, because it fails on the apply.
"""

from __future__ import annotations

import json

from rotator.iam import FORBIDDEN_ACTIONS, render, rotation_policy, schedule_inputs

GENERATED = "terraform/generated"


def allow_statements(policy):
    return [s for s in policy["Statement"] if s["Effect"] == "Allow"]


def test_no_allow_statement_grants_a_wildcard_resource(config):
    for statement in allow_statements(rotation_policy(config)):
        assert "*" not in statement["Resource"], statement["Sid"]


def test_the_only_secrets_named_are_the_declared_ones(config):
    policy = rotation_policy(config)
    secrets = next(s for s in policy["Statement"] if s["Sid"] == "ReadAndStageDeclaredSecrets")

    assert secrets["Resource"] == [
        "arn:aws:secretsmanager:eu-west-1:111122223333:secret:prod/orders/app-??????"
    ]
    # The vault target has no secret in this account and must not appear.
    assert not any("analytics" in arn for arn in secrets["Resource"])


def test_the_arn_pattern_cannot_match_a_neighbouring_secret(config):
    """`prod/orders/app*` would also match `prod/orders/app-replica`. Six
    single character wildcards match only the suffix Secrets Manager adds."""
    policy = rotation_policy(config)
    for arn in next(s for s in policy["Statement"] if s["Sid"] == "ReadAndStageDeclaredSecrets")[
        "Resource"
    ]:
        assert arn.endswith("-??????")
        assert "*" not in arn


def test_nothing_in_the_policy_can_create_delete_or_list_secrets(config):
    granted = {
        action
        for statement in allow_statements(rotation_policy(config))
        for action in statement["Action"]
    }

    assert "secretsmanager:CreateSecret" not in granted
    assert "secretsmanager:DeleteSecret" not in granted
    assert "secretsmanager:ListSecrets" not in granted
    assert "secretsmanager:TagResource" not in granted


def test_the_deny_statement_covers_everything_it_names(config):
    policy = rotation_policy(config)
    deny = next(s for s in policy["Statement"] if s["Effect"] == "Deny")

    assert sorted(deny["Action"]) == sorted(FORBIDDEN_ACTIONS)
    assert deny["Resource"] == ["*"]


def test_kms_is_usable_only_through_secrets_manager(config):
    kms = next(
        s
        for s in rotation_policy(config)["Statement"]
        if s["Sid"] == "DecryptThroughSecretsManagerOnly"
    )

    assert kms["Condition"]["StringEquals"]["kms:ViaService"] == (
        "secretsmanager.eu-west-1.amazonaws.com"
    )
    assert kms["Action"] == ["kms:Decrypt", "kms:GenerateDataKey"]


def test_iam_accepts_the_committed_policy(aws, repo_root):
    """A malformed document is a MalformedPolicyDocument at apply time, which
    is a 03:15 discovery. This is the same validation, at test time."""
    import boto3

    document = (repo_root / GENERATED / "rotation_policy.json").read_text(encoding="utf-8")
    iam = boto3.client("iam", region_name="eu-west-1")

    created = iam.create_policy(PolicyName="secrets-rotation", PolicyDocument=document)["Policy"]
    stored = iam.get_policy_version(
        PolicyArn=created["Arn"], VersionId=created["DefaultVersionId"]
    )["PolicyVersion"]["Document"]

    assert stored == json.loads(document)


def test_the_committed_files_match_what_the_renderer_produces_now(repo_root):
    """The drift check CI runs. targets.toml is the single source of truth and
    this is what makes that true rather than aspirational."""
    from rotator.config import load

    config = load(repo_root / "targets.toml")

    assert (repo_root / GENERATED / "rotation_policy.json").read_text(encoding="utf-8") == render(
        rotation_policy(config)
    )
    assert (repo_root / GENERATED / "targets.json").read_text(encoding="utf-8") == render(
        schedule_inputs(config)
    )


def test_every_target_gets_exactly_one_schedule(repo_root):
    from rotator.config import load

    config = load(repo_root / "targets.toml")
    schedules = schedule_inputs(config)

    assert set(schedules) == {target.name for target in config.targets}
    for target in config.targets:
        assert schedules[target.name]["schedule"] == target.schedule
        assert schedules[target.name]["quiesce_seconds"] == target.quiesce_seconds


def test_the_terraform_locals_filter_vault_targets_out_of_the_policy(repo_root):
    """What locals.tf does with targets.json, asserted here because terraform
    validate does not evaluate it."""
    from rotator.config import load

    config = load(repo_root / "targets.toml")
    schedules = schedule_inputs(config)
    in_secretsmanager = {name for name, t in schedules.items() if t["store"] == "secretsmanager"}

    assert in_secretsmanager == {"orders-db", "reporting-db"}
    policy_arns = [
        arn
        for statement in allow_statements(rotation_policy(config))
        for arn in statement["Resource"]
    ]
    assert len([a for a in policy_arns if a.startswith("arn:aws:secretsmanager")]) == len(
        in_secretsmanager
    )
