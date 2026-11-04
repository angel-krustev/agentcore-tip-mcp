# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

/**
 * AgentCore-TIP-MCP-Broker identity stack: the three IAM roles the PEP depends on.
 *
 *  1. OIDC bootstrap role  (OIDC_ROLE_ARN) - Plane A; assumed with the user's IDP JWT, only calls CreateTokenWithIAM.
 *  2. Enhanced carrier role (TIP_ROLE_ARN) - Plane B target; Lake Formation, Athena, Redshift Serverless,
 *                                             S3 Access Grants, optional Bedrock. Nothing else.
 *  3. PEP base role                        - ambient identity (ECS task role / local credentials) that signs
 *                                             the AssumeRole call on the carrier role. No data permissions.
 *
 * Creates NEW roles; the pre-existing idp-stack roles are neither referenced nor modified.
 * Mirrors iam/agentcore-tip-identity-stack.yml.
 *
 * Usage:
 *   terraform init
 *   terraform apply \
 *     -var 'oidc_provider_arn=arn:aws:iam::<acct>:oidc-provider/login.microsoftonline.com/<tenant>/v2.0' \
 *     -var 'oidc_audiences=["<client-id>"]'
 */

terraform {
  required_version = ">= 1.3"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.name

  oidc_host = element(split("oidc-provider/", var.oidc_provider_arn), 1)

  has_local_dev = length(var.local_dev_principal_arns) > 0

  tags = {
    Project   = "AgentCore-TIP-MCP-Broker"
    ManagedBy = "Terraform"
  }

  carrier_actions = ["sts:AssumeRole", "sts:SetContext", "sts:SetSourceIdentity"]
}

#####################################################################
# (1) OIDC bootstrap role  ->  OIDC_ROLE_ARN
#####################################################################
resource "aws_iam_role" "oidc" {
  name                 = "${var.name_prefix}-OIDCRole"
  description          = "Plane A bootstrap. Assumed with the IDP JWT; only calls CreateTokenWithIAM."
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowWebIdentityFromIdp"
        Effect    = "Allow"
        Principal = { Federated = var.oidc_provider_arn }
        Action    = ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"]
        Condition = { StringEquals = { "${local.oidc_host}:aud" = var.oidc_audiences } }
      },
      {
        Sid       = "AllowSourceIdentityFromIdp"
        Effect    = "Allow"
        Principal = { Federated = var.oidc_provider_arn }
        Action    = "sts:SetSourceIdentity"
        Condition = { StringEquals = { "${local.oidc_host}:aud" = var.oidc_audiences } }
      }
    ]
  })

  tags = merge(local.tags, { Component = "oidc-bootstrap" })
}

resource "aws_iam_role_policy" "oidc_create_token" {
  name = "create-token-with-iam"
  role = aws_iam_role.oidc.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ExchangeIdpTokenForIdentityContext"
        Effect   = "Allow"
        Action   = "sso-oauth:CreateTokenWithIAM"
        Resource = "*"
      }
    ]
  })
}

# Separate resource so the OIDC role does not depend on the carrier role (and vice versa).
resource "aws_iam_role_policy" "oidc_assume_carrier" {
  count = var.allow_oidc_role_to_assume_carrier ? 1 : 0

  name = "assume-enhanced-role"
  role = aws_iam_role.oidc.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = local.carrier_actions
        Resource = aws_iam_role.enhanced.arn
      }
    ]
  })
}

#####################################################################
# (2) Enhanced (carrier) role  ->  TIP_ROLE_ARN
#####################################################################
resource "aws_iam_role" "enhanced" {
  name        = "${var.name_prefix}-IdEnhancedRole"
  description = "Plane B carrier role. Lake Formation, Athena, Redshift Serverless, S3 Access Grants, optional Bedrock."
  # Chained from the PEP base role, so AWS caps it at 1 hour anyway; the PEP requests 900 s.
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid       = "AllowPepAssumeWithIdentityContext"
          Effect    = "Allow"
          Principal = { AWS = aws_iam_role.pep.arn }
          Action    = local.carrier_actions
        }
      ],
      var.allow_oidc_role_to_assume_carrier ? [
        {
          Sid       = "AllowOidcRoleLegacyExchange"
          Effect    = "Allow"
          Principal = { AWS = aws_iam_role.oidc.arn }
          Action    = local.carrier_actions
        }
      ] : []
    )
  })

  tags = merge(local.tags, { Component = "carrier" })
}

resource "aws_iam_role_policy" "enhanced_data_plane" {
  name = "agentcore-tip-data-plane"
  role = aws_iam_role.enhanced.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        # Lake Formation: no resource-level scoping; LF enforces the user's own grants.
        {
          Sid      = "LakeFormationDataAccess"
          Effect   = "Allow"
          Action   = "lakeformation:GetDataAccess"
          Resource = "*"
        },

        # Athena
        {
          Sid    = "AthenaWorkgroupQueries"
          Effect = "Allow"
          Action = [
            "athena:StartQueryExecution",
            "athena:GetQueryExecution",
            "athena:GetQueryResults",
            "athena:GetQueryResultsStream",
            "athena:StopQueryExecution",
            "athena:GetWorkGroup",
          ]
          Resource = "arn:${local.partition}:athena:${local.region}:${local.account_id}:workgroup/${var.athena_workgroup}"
        },
        {
          Sid      = "AthenaDiscovery"
          Effect   = "Allow"
          Action   = ["athena:ListDataCatalogs", "athena:ListDatabases", "athena:ListWorkGroups"]
          Resource = "*"
        },

        # Glue Data Catalog, read only (needed by Athena and Redshift Spectrum)
        {
          Sid    = "GlueCatalogRead"
          Effect = "Allow"
          Action = [
            "glue:GetDatabase",
            "glue:GetDatabases",
            "glue:GetTable",
            "glue:GetTables",
            "glue:GetTableVersion",
            "glue:GetTableVersions",
            "glue:GetPartition",
            "glue:GetPartitions",
            "glue:BatchGetPartition",
          ]
          Resource = [
            "arn:${local.partition}:glue:${local.region}:${local.account_id}:catalog",
            "arn:${local.partition}:glue:${local.region}:${local.account_id}:database/*",
            "arn:${local.partition}:glue:${local.region}:${local.account_id}:table/*/*",
          ]
        },

        # S3 Access Grants: data-plane consumer actions only, no grant administration
        {
          Sid      = "S3AccessGrantsInstance"
          Effect   = "Allow"
          Action   = ["s3:GetAccessGrantsInstanceForPrefix"]
          Resource = "arn:${local.partition}:s3:${local.region}:${local.account_id}:access-grants/default"
        },
        {
          Sid      = "S3AccessGrantsCaller"
          Effect   = "Allow"
          Action   = ["s3:GetDataAccess", "s3:ListCallerAccessGrants"]
          Resource = "*"
        },

        # Redshift Serverless via the Data API
        {
          Sid      = "RedshiftDataExecute"
          Effect   = "Allow"
          Action   = ["redshift-data:ExecuteStatement", "redshift-data:BatchExecuteStatement"]
          Resource = "arn:${local.partition}:redshift-serverless:${local.region}:${local.account_id}:workgroup/${var.redshift_workgroup_name}"
        },
        # These actions do not support resource-level permissions; statements are still
        # bound to the calling identity by the Data API.
        {
          Sid    = "RedshiftDataStatementAccess"
          Effect = "Allow"
          Action = [
            "redshift-data:DescribeStatement",
            "redshift-data:GetStatementResult",
            "redshift-data:CancelStatement",
            "redshift-data:ListStatements",
            "redshift-data:ListDatabases",
            "redshift-data:ListSchemas",
            "redshift-data:ListTables",
            "redshift-data:DescribeTable",
          ]
          Resource = "*"
        },
      ],

      # Athena results bucket (only when the caller writes results)
      var.athena_results_bucket_name != "" ? [
        {
          Sid    = "AthenaResultsBucket"
          Effect = "Allow"
          Action = [
            "s3:GetBucketLocation",
            "s3:ListBucket",
            "s3:GetObject",
            "s3:PutObject",
            "s3:AbortMultipartUpload",
          ]
          Resource = [
            "arn:${local.partition}:s3:::${var.athena_results_bucket_name}",
            "arn:${local.partition}:s3:::${var.athena_results_bucket_name}/*",
          ]
        }
      ] : [],

      # Bedrock (optional)
      var.enable_bedrock ? [
        {
          Sid      = "BedrockInvokeModel"
          Effect   = "Allow"
          Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
          Resource = "arn:${local.partition}:bedrock:${local.region}::foundation-model/${var.bedrock_model_id}"
        }
      ] : []
    )
  })
}

#####################################################################
# (3) PEP base role (Fargate task role / local credentials)
#####################################################################
resource "aws_iam_role" "pep" {
  name                 = "${var.name_prefix}-PepServiceRole"
  description          = "Base identity for the AgentCore-TIP-MCP-Broker PEP; may only assume the enhanced role."
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      var.trust_ecs_tasks ? [
        {
          Sid       = "AllowEcsTasks"
          Effect    = "Allow"
          Principal = { Service = "ecs-tasks.amazonaws.com" }
          Action    = "sts:AssumeRole"
          Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
        }
      ] : [],
      local.has_local_dev && !var.local_dev_require_mfa ? [
        {
          Sid       = "AllowLocalDev"
          Effect    = "Allow"
          Principal = { AWS = var.local_dev_principal_arns }
          Action    = "sts:AssumeRole"
        }
      ] : [],
      local.has_local_dev && var.local_dev_require_mfa ? [
        {
          Sid       = "AllowLocalDevWithMfa"
          Effect    = "Allow"
          Principal = { AWS = var.local_dev_principal_arns }
          Action    = "sts:AssumeRole"
          Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
        }
      ] : []
    )
  })

  tags = merge(local.tags, { Component = "pep" })
}

# SetContext carries the Identity Center assertion (ProvidedContexts); SetSourceIdentity stamps
# the agent role for CloudTrail. The PEP passes no session tags, so no TagSession.
resource "aws_iam_role_policy" "pep_assume_carrier" {
  name = "pep-assume-enhanced-role"
  role = aws_iam_role.pep.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AssumeEnhancedRoleWithIdentityContext"
        Effect   = "Allow"
        Action   = local.carrier_actions
        Resource = aws_iam_role.enhanced.arn
      }
    ]
  })
}
