"""The IAM policy and the schedule list, rendered from targets.toml.

Terraform could build both with `data.aws_iam_policy_document` and a `for_each`
over a variable, and then targets.toml and the tfvars would be two files that
have to agree. They are rendered here instead and committed under
terraform/generated/, so there is one list of targets in the repo.

What that gives up is the ability to change a schedule by editing Terraform.
`scripts/render.py` has to run first, and CI fails if the committed output
differs from what the renderer produces now.
"""

from __future__ import annotations

import json
from typing import Any

from .config import Config

POLICY_VERSION = "2012-10-17"

#: Everything a rotation does to a secret, and nothing else. Nothing here
#: creates, deletes, tags or replicates one.
SECRET_ACTIONS = (
    "secretsmanager:DescribeSecret",
    "secretsmanager:GetSecretValue",
    "secretsmanager:ListSecretVersionIds",
    "secretsmanager:PutSecretValue",
    "secretsmanager:UpdateSecretVersionStage",
)

#: Denied outright, on everything. An explicit Deny cannot be undone by a
#: later Allow, which is the point: the role is one policy attachment away
#: from being able to delete the secrets it rotates, and this closes that.
FORBIDDEN_ACTIONS = (
    "secretsmanager:DeleteResourcePolicy",
    "secretsmanager:DeleteSecret",
    "secretsmanager:PutResourcePolicy",
    "secretsmanager:RemoveRegionsFromReplication",
    "secretsmanager:ReplicateSecretToRegions",
)


def rotation_policy(config: Config) -> dict[str, Any]:
    statements: list[dict[str, Any]] = []

    secret_arns = [config.aws.secret_arn(secret_id) for secret_id in config.secret_ids]
    if secret_arns:
        statements.append(
            {
                "Sid": "ReadAndStageDeclaredSecrets",
                "Effect": "Allow",
                "Action": list(SECRET_ACTIONS),
                "Resource": secret_arns,
            }
        )
        # ListSecrets is deliberately absent. It takes no resource, so granting
        # it means granting it on everything, and nothing here needs it: the
        # targets are declared rather than discovered.
        statements.append(
            {
                "Sid": "DecryptThroughSecretsManagerOnly",
                "Effect": "Allow",
                "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
                "Resource": [config.aws.kms_key_arn],
                "Condition": {
                    "StringEquals": {
                        "kms:ViaService": f"secretsmanager.{config.aws.region}.amazonaws.com"
                    }
                },
            }
        )

    statements.append(
        {
            "Sid": "NeverDeleteOrShareASecret",
            "Effect": "Deny",
            "Action": list(FORBIDDEN_ACTIONS),
            "Resource": ["*"],
        }
    )
    return {"Version": POLICY_VERSION, "Statement": statements}


def schedule_inputs(config: Config) -> dict[str, Any]:
    """What Terraform iterates over to declare one schedule per target.

    The quiesce window is in here as well as in targets.toml, because it sets
    how long the task can run and therefore the schedule's own timeout. A
    schedule that gives up after five minutes on a target that sleeps for an
    hour kills the rotation between promote and revoke, which is the one place
    it must not be killed.
    """
    return {
        target.name: {
            "key": target.key,
            "max_age_days": target.max_age_days,
            "quiesce_seconds": target.quiesce_seconds,
            "schedule": target.schedule,
            "store": target.store,
        }
        for target in sorted(config.targets, key=lambda t: t.name)
    }


def render(document: dict[str, Any]) -> str:
    """Byte for byte what the committed files hold, so a diff means a change."""
    return json.dumps(document, indent=2, sort_keys=False) + "\n"
