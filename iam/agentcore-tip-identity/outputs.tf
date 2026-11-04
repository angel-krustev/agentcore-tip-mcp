# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

output "oidc_role_arn" {
  description = "Set as OIDC_ROLE_ARN."
  value       = aws_iam_role.oidc.arn
}

output "enhanced_role_arn" {
  description = "Set as TIP_ROLE_ARN (carrier role)."
  value       = aws_iam_role.enhanced.arn
}

output "pep_service_role_arn" {
  description = "Use as the Fargate task role (taskRoleArn) or assume locally to obtain base credentials."
  value       = aws_iam_role.pep.arn
}
