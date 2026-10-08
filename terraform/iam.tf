data "aws_caller_identity" "current" {}

# The rendered policy names secret ARNs with an account id baked in. Applying
# it in a different account produces a role with permissions on nothing, which
# fails at 03:15 on a Sunday rather than here.
resource "terraform_data" "account_guard" {
  input = data.aws_caller_identity.current.account_id

  lifecycle {
    precondition {
      condition     = local.policy_accounts == [data.aws_caller_identity.current.account_id]
      error_message = "generated/rotation_policy.json is for account(s) ${join(", ", local.policy_accounts)}, this is ${data.aws_caller_identity.current.account_id}. Fix [aws].account_id in targets.toml and re-run scripts/render.py."
    }
  }
}

data "aws_iam_policy_document" "task_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    # Without this the role can be assumed on behalf of any task in the
    # account, which is every workload that shares the cluster.
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:ecs:*:${data.aws_caller_identity.current.account_id}:*"]
    }
  }
}

resource "aws_iam_role" "rotator" {
  name               = "${var.name_prefix}-task"
  description        = "Assumed by the rotation task. Policy rendered from targets.toml."
  assume_role_policy = data.aws_iam_policy_document.task_assume.json
}

# Inline rather than a managed policy attachment. A managed policy can be
# attached to something else; this one cannot outlive the role it is for.
resource "aws_iam_role_policy" "rotator" {
  name   = "${var.name_prefix}-secrets"
  role   = aws_iam_role.rotator.id
  policy = file("${path.module}/generated/rotation_policy.json")
}

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${var.name_prefix}-scheduler"
  description        = "Assumed by EventBridge Scheduler to start the rotation task"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

data "aws_iam_policy_document" "scheduler" {
  statement {
    sid       = "RunOnlyTheRotationTask"
    actions   = ["ecs:RunTask"]
    resources = ["${var.task_definition_arn}:*", var.task_definition_arn]

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [var.cluster_arn]
    }
  }

  # RunTask with a task role is a privilege escalation unless PassRole is
  # restricted: the scheduler could otherwise start a task as any role in the
  # account, including one that can read every secret.
  statement {
    sid       = "PassOnlyTheseTwoRoles"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.rotator.arn, var.task_execution_role_arn]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "scheduler" {
  name   = "${var.name_prefix}-run-task"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.scheduler.json
}
