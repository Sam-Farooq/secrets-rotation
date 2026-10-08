locals {
  # Both files are rendered from ../targets.toml by scripts/render.py. CI runs
  # that script with --check, so a stale file here fails before an apply can
  # grant a permission the Python side does not know about.
  targets = jsondecode(file("${path.module}/generated/targets.json"))
  policy  = jsondecode(file("${path.module}/generated/rotation_policy.json"))

  # Vault targets have no secret in this account, so they appear in the
  # schedules and not in the policy.
  secretsmanager_targets = {
    for name, target in local.targets : name => target if target.store == "secretsmanager"
  }

  allow_resources = flatten([
    for statement in local.policy.Statement : statement.Resource
    if statement.Effect == "Allow"
  ])

  policy_accounts = distinct([
    for arn in local.allow_resources : split(":", arn)[4]
  ])
}
