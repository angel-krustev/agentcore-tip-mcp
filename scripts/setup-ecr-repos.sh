#!/bin/bash
# ==============================================================================
# Setup script for ECR repositories
# ==============================================================================
# Creates the agentcore-tip-mcp-test and agentcore-tip-mcp repos
# if they don't already exist.
#
# Usage:
#   ./scripts/setup-ecr-repos.sh
# ==============================================================================

set -euo pipefail

AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_PROFILE="${AWS_PROFILE:-default}"

echo "Setting up private ECR repositories in $AWS_REGION using profile $AWS_PROFILE ..."

ensure_repository() {
  local repository_name="$1"
  local environment="$2"

  if ! aws ecr describe-repositories \
    --repository-names "$repository_name" \
    --region "$AWS_REGION" \
    --profile "$AWS_PROFILE" >/dev/null 2>&1; then
    aws ecr create-repository \
      --repository-name "$repository_name" \
      --region "$AWS_REGION" \
      --profile "$AWS_PROFILE" \
      --image-scanning-configuration scanOnPush=true \
      --tags "Key=Project,Value=AgentCore-TIP-MCP-Broker" "Key=Environment,Value=$environment"
  fi

  repository_arn="$(aws ecr describe-repositories \
    --repository-names "$repository_name" \
    --region "$AWS_REGION" \
    --profile "$AWS_PROFILE" \
    --query 'repositories[0].repositoryArn' \
    --output text)"
  aws ecr tag-resource \
    --resource-arn "$repository_arn" \
    --region "$AWS_REGION" \
    --profile "$AWS_PROFILE" \
    --tags "Key=Project,Value=AgentCore-TIP-MCP-Broker" "Key=Environment,Value=$environment"
  aws ecr put-image-scanning-configuration \
    --repository-name "$repository_name" \
    --region "$AWS_REGION" \
    --profile "$AWS_PROFILE" \
    --image-scanning-configuration scanOnPush=TRUE
}

ensure_repository agentcore-tip-mcp-test test
ensure_repository agentcore-tip-mcp production

# Lifecycle policy: expire untagged test images older than 30 days
LIFECYCLE_POLICY='{
  "rules": [
    {
      "rulePriority": 1,
      "description": "Expire untagged test images after 30 days",
      "selection": {
        "tagStatus": "untagged",
        "countType": "sinceImagePushed",
        "countUnit": "days",
        "countNumber": 30
      },
      "action": { "type": "expire" }
    }
  ]
}'

aws ecr put-lifecycle-policy \
  --repository-name agentcore-tip-mcp-test \
  --region "$AWS_REGION" \
  --profile "$AWS_PROFILE" \
  --lifecycle-policy-text "$LIFECYCLE_POLICY"

echo "✅ ECR repositories ready:"
echo "  - agentcore-tip-mcp-test (private test builds)"
echo "  - agentcore-tip-mcp (private promoted image)"
