output "task_role_arn" {
  description = "Role the rotation task runs as. Grant the database nothing through it."
  value       = aws_iam_role.rotator.arn
}

output "scheduler_role_arn" {
  description = "Role EventBridge Scheduler assumes to start the task"
  value       = aws_iam_role.scheduler.arn
}

output "schedule_names" {
  description = "One schedule per target in targets.toml"
  value       = sort([for schedule in aws_scheduler_schedule.rotation : schedule.name])
}

output "rotated_secret_arns" {
  description = "Exactly what the task role may read and stage"
  value       = local.allow_resources
}

output "secretsmanager_targets" {
  description = "Targets whose credential lives in Secrets Manager. The rest are in Vault and are not in the policy above."
  value       = sort(keys(local.secretsmanager_targets))
}
