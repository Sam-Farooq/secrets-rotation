# One schedule per target in targets.toml. The schedule expression comes from
# that file, so a cadence change is a Python-side edit plus scripts/render.py.

resource "aws_scheduler_schedule" "rotation" {
  for_each = local.targets

  name        = "${var.name_prefix}-${each.key}"
  description = "Rotate ${each.value.key} every ${each.value.max_age_days} days at most"
  state       = var.schedule_state
  group_name  = "default"

  schedule_expression          = each.value.schedule
  schedule_expression_timezone = var.schedule_timezone

  # OFF, not a flexible window. The runbook names a time, and an on-call
  # engineer reading an audit line at 03:40 should not have to work out
  # whether the schedule decided to drift by fifteen minutes.
  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = var.cluster_arn
    role_arn = aws_iam_role.scheduler.arn

    ecs_parameters {
      task_definition_arn = var.task_definition_arn
      launch_type         = "FARGATE"
      task_count          = 1

      network_configuration {
        subnets          = var.subnet_ids
        security_groups  = var.security_group_ids
        assign_public_ip = false
      }
    }

    # The container runs one target. Running all of them in one task means a
    # failure on the first leaves the rest unrotated and reports once.
    input = jsonencode({
      containerOverrides = [
        {
          name    = var.container_name
          command = ["rotator", "rotate", "--target", each.key, "--confirm", "--audit", "/var/log/rotator/${each.key}.audit.jsonl"]
          environment = [
            {
              name  = "ROTATOR_QUIESCE_SECONDS"
              value = tostring(each.value.quiesce_seconds)
            },
          ]
        },
      ]
    })

    # Zero retries, deliberately. A schedule cannot tell a task that failed to
    # start from one that failed between promote and revoke, and retrying the
    # second starts a fresh rotation on a target that already has a staged
    # credential. That run refuses and reports blocked, which is correct and
    # is also three alerts for one incident. The dead letter queue is how a
    # failed invocation becomes visible instead.
    retry_policy {
      maximum_retry_attempts       = 0
      maximum_event_age_in_seconds = 60
    }

    dynamic "dead_letter_config" {
      for_each = var.dead_letter_queue_arn == null ? [] : [var.dead_letter_queue_arn]

      content {
        arn = dead_letter_config.value
      }
    }
  }
}

# Deliberately not used: aws_secretsmanager_secret_rotation.
#
# That resource is Secrets Manager's own rotation, and it can only invoke a
# Lambda. The two phase sequence here sleeps for the quiesce window, which is
# an hour on reporting-db, and the Lambda ceiling is fifteen minutes.
#
# What that gives up is the console: RotationEnabled stays false on every
# secret listed here, the Rotation tab says rotation is not configured, and
# anyone auditing through the console will believe it. The compensating
# control is the schedules above and the audit file, and the answer to "when
# did this last rotate" is the CreatedDate of the AWSCURRENT version, which is
# what `rotator plan` reads.
