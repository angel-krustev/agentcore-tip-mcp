# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

/**
 * TIP Enhanced IAM role with tag-gated capabilities.
 *
 * Single role approach: TIP injects session tags (tp:approved-for-*) during
 * authentication; each capability (Bedrock, Athena, S3, Glue) is gated behind
 * the corresponding tag key via aws:PrincipalTag conditions.
 *
 * Usage:
 *   terraform apply -var="role_name=idp-stack-IdEnhancedRole"
 */

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}

variable "role_name" {
  description = "Name of the IAM role"
  type        = string
  default     = "idp-stack-IdEnhancedRole"
}

variable "bedrock_model_region" {
  description = "AWS region for Bedrock resource ARN"
  type        = string
  default     = "us-east-1"
}

locals {
  tag_condition_bedrock = {
    ForAllValues:StringEquals = {
      "aws:PrincipalTag/tp:approved-for-bedrock" = "true"
    }
  }
  tag_condition_athena = {
    ForAllValues:StringEquals = {
      "aws:PrincipalTag/tp:approved-for-athena" = "true"
    }
  }
  tag_condition_s3 = {
    ForAllValues:StringEquals = {
      "aws:PrincipalTag/tp:approved-for-s3" = "true"
    }
  }

  trust_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSSOAssumeRoleWithTagSession"
        Effect    = "Allow"
        Action    = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
        Principal = {
          Service = "sso.amazonaws.com"
        }
      }
    ]
  })

  capabilities_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowBedrockIfTipApproved"
        Effect    = "Allow"
        Action    = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = "arn:aws:bedrock:${var.bedrock_model_region}:::foundation-model/*"
        Condition = local.tag_condition_bedrock
      },
      {
        Sid       = "AllowAthenaIfTipApproved"
        Effect    = "Allow"
        Action    = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:StopQueryExecution"
        ]
        Resource = "*"
        Condition = local.tag_condition_athena
      },
      {
        Sid       = "AllowS3IfTipApproved"
        Effect    = "Allow"
        Action    = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource  = "*"
        Condition = local.tag_condition_s3
      },
      {
        Sid       = "AllowS3LoggingForAthena"
        Effect    = "Allow"
        Action    = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource  = "*"
        Condition = local.tag_condition_athena
      },
      {
        Sid       = "AllowGlueForAthena"
        Effect    = "Allow"
        Action    = [
          "glue:GetTable",
          "glue:GetDatabase",
          "glue:GetPartitions"
        ]
        Resource  = "*"
        Condition = local.tag_condition_athena
      }
    ]
  })
}

resource "aws_iam_role" "tip_enhanced" {
  name               = var.role_name
  assume_role_policy = local.trust_policy

  tags = {
    Project   = "AgentCore-TIP-MCP-Broker"
    ManagedBy = "Terraform"
  }
}

resource "aws_iam_role_policy" "tag_gated_capabilities" {
  name   = "tip-session-tag-capabilities"
  role   = aws_iam_role.tip_enhanced.id
  policy = local.capabilities_policy
}

output "role_arn" {
  description = "ARN of the TIP Enhanced Role"
  value       = aws_iam_role.tip_enhanced.arn
}

output "role_name" {
  description = "Name of the role"
  value       = aws_iam_role.tip_enhanced.name
}
