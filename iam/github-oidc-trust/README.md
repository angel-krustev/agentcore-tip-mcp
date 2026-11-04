# GitHub Actions OIDC Trust Policy

This policy allows GitHub Actions workflows in the `angel-krustev/agentcore-tip-mcp`
repository to assume an IAM role without storing long-lived AWS credentials.

## Prerequisites

Find your AWS account ID:
```bash
aws sts get-caller-identity --query Account --output text
```

## Step 1 — Register GitHub OIDC Provider

AWS needs to trust tokens from GitHub Actions. Check if it's already registered:

```bash
aws iam list-open-id-connect-providers | grep github
```

If nothing returns, create it:

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com
```

## Step 2 — Create Private ECR Repositories

```bash
AWS_PROFILE=default AWS_REGION=us-east-1 ./scripts/setup-ecr-repos.sh
```

## Step 3 — Edit the Policies

In [`trust-policy.json`](trust-policy.json), replace `<AWS_ACCOUNT_ID>` with your
account ID. In [`policy.json`](policy.json), replace `<AWS_ACCOUNT_ID>` and
`<AWS_REGION>`; keep the repository subject restricted to your GitHub repository
and deployment branch.

## Step 4 — Create the IAM Role

```bash
aws iam create-role \
  --role-name agentcore-tip-mcp-github-oidc \
  --assume-role-policy-document file://trust-policy.json \
  --description "GitHub Actions OIDC role for AgentCore-TIP-MCP-Broker ECR deployments" \
  --tags Key=Project,Value=AgentCore-TIP-MCP-Broker
```

> If the role already exists you'll get `EntityAlreadyExists` — that's fine, skip
> to Step 5 to update its trust policy.

## Step 5 — Update the Trust Policy (if role already exists)

```bash
aws iam update-assume-role-policy \
  --role-name agentcore-tip-mcp-github-oidc \
  --policy-document file://trust-policy.json
```

## Step 6 — Attach ECR Push Permissions

```bash
aws iam put-role-policy \
  --role-name agentcore-tip-mcp-github-oidc \
  --policy-name ECRPush \
  --policy-document file://policy.json
```

## Step 7 — Add GitHub Secret

1. Go to **Settings → Secrets and variables → Actions**
2. Click **"New repository secret"**
3. Add:
   - **Name:** `AWS_ROLE_ARN`
   - **Secret:** `arn:aws:iam::<YOUR_ACCOUNT_ID>:role/agentcore-tip-mcp-github-oidc`

## Step 8 — Verify

Push to `main` or trigger the workflow manually from the **Actions** tab. The
workflow will:

1. Authenticate to AWS via OIDC
2. Build and push the ARM64 test image
3. Validate that the test image exists

The test and promoted images are in private ECR by default. The `ecr:CreateRepository`
permission is limited to creating a repository tagged for this project and production.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| "The role does not exist" | Verify the role name matches in the trust policy |
| "No ECR repository found" | Run step 1 to create the repositories first |
| "Token is invalid" | Confirm the OIDC provider exists: `aws iam list-open-id-connect-providers` |
| Workflow fails on `buildx` | Make sure GitHub Actions is using `ubuntu-latest` (ARM64 cross-build is supported) |
