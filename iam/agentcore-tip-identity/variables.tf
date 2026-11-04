# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

variable "name_prefix" {
  description = "Prefix for role names (<prefix>-OIDCRole, <prefix>-IdEnhancedRole, <prefix>-PepServiceRole)."
  type        = string
  default     = "agentcore-tip"

  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9+=,.@_-]{0,24}$", var.name_prefix))
    error_message = "name_prefix must start with a letter and be at most 25 characters of [A-Za-z0-9+=,.@_-]."
  }
}

variable "oidc_provider_arn" {
  description = "Existing IAM OIDC provider for the IDP, e.g. arn:aws:iam::<acct>:oidc-provider/login.microsoftonline.com/<tenant>/v2.0. Referenced, not created."
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:oidc-provider/.+$", var.oidc_provider_arn))
    error_message = "oidc_provider_arn must be an IAM OIDC provider ARN."
  }
}

variable "oidc_audiences" {
  description = "Token audiences (client ids) accepted by the OIDC role."
  type        = list(string)

  validation {
    condition     = length(var.oidc_audiences) > 0
    error_message = "At least one audience is required."
  }
}

variable "athena_workgroup" {
  description = "Athena workgroup the carrier role may use. Must match the PEP ATHENA_WORKGROUP setting."
  type        = string
  default     = "idc-wg"
}

variable "athena_results_bucket_name" {
  description = "Optional S3 bucket for Athena results when the caller (not the workgroup) writes them. Empty = no S3 results statement."
  type        = string
  default     = ""
}

variable "redshift_workgroup_name" {
  description = "Redshift Serverless workgroup name for the Data API (\"*\" = any workgroup in this account/region)."
  type        = string
  default     = "*"
}

variable "enable_bedrock" {
  description = "Grant bedrock:InvokeModel on bedrock_model_id to the carrier role."
  type        = bool
  default     = false
}

variable "bedrock_model_id" {
  description = "Foundation model id invocable through the carrier role (used only when enable_bedrock is true)."
  type        = string
  default     = "amazon.nova-lite-v1:0"
}

variable "allow_oidc_role_to_assume_carrier" {
  description = "Legacy single-call exchange() path only: let the OIDC role assume the carrier role directly. The PEP (Plane A + Plane B) does not need this."
  type        = bool
  default     = false
}

variable "trust_ecs_tasks" {
  description = "Allow ecs-tasks.amazonaws.com to assume the PEP base role (Fargate task role)."
  type        = bool
  default     = true
}

variable "local_dev_principal_arns" {
  description = "Optional IAM user/role ARNs allowed to assume the PEP base role for local container runs. Leave empty in deployed environments."
  type        = list(string)
  default     = []
}

variable "local_dev_require_mfa" {
  description = "Require MFA when local_dev_principal_arns assume the PEP base role."
  type        = bool
  default     = false
}
