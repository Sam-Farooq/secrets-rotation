# Five of these have no default, because none of them has a safe one. The
# cluster and the task definition belong to whoever runs the platform; this
# module declares when the job runs and what it is allowed to touch, and
# nothing about the image it runs.

variable "name_prefix" {
  description = "Prefix for the role and schedule names"
  type        = string
  default     = "secrets-rotation"
}

variable "cluster_arn" {
  description = "ECS cluster the rotation task runs on"
  type        = string
}

variable "task_definition_arn" {
  description = "Task definition that runs `rotator rotate`"
  type        = string
}

variable "task_execution_role_arn" {
  description = "Execution role on that task definition, needed for PassRole"
  type        = string
}

variable "container_name" {
  description = "Container in the task definition to override the command on"
  type        = string
}

variable "subnet_ids" {
  description = "Private subnets with a route to Secrets Manager and the database"
  type        = list(string)

  validation {
    condition     = length(var.subnet_ids) > 0
    error_message = "At least one subnet is required."
  }
}

variable "security_group_ids" {
  description = "Security groups allowing egress to the database and to AWS APIs"
  type        = list(string)

  validation {
    condition     = length(var.security_group_ids) > 0
    error_message = "At least one security group is required."
  }
}

variable "dead_letter_queue_arn" {
  description = "SQS queue for schedule invocations that never started a task"
  type        = string
  default     = null
}

variable "schedule_timezone" {
  description = "Timezone the cron expressions in targets.toml are written in"
  type        = string
  default     = "UTC"
}

variable "schedule_state" {
  description = "ENABLED or DISABLED, for every schedule at once"
  type        = string
  default     = "ENABLED"

  validation {
    condition     = contains(["ENABLED", "DISABLED"], var.schedule_state)
    error_message = "schedule_state must be ENABLED or DISABLED."
  }
}
