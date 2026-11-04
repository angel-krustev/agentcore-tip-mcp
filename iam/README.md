# TIP-Controlled Bedrock Access via Session Tags

## Overview

Use a **single IAM role** with TIP (Token Issuance Protection) to dynamically control which AWS services a session can access — including Bedrock model invocation. TIP evaluates the authentication context and injects session tags into the credentials. The role's inline policy then gates each capability behind those tags.

## Why This Approach

| Without TIP Tags | With TIP Tags |
|---|---|
| Role grants Bedrock access to **everyone** who receives credentials | Role grants Bedrock access **only if** TIP approved and tagged the session |
| Static, all-or-nothing permission | Dynamic, context-aware permission |
| Multiple roles needed to separate capabilities | Single role, tag-gated capabilities |

## Architecture

```
Entra ID MFA Token ─────┐
                        ├──→ TIP evaluates context & attributes
TIP Configuration ──────┤  ├──→ passes session tags:
                        │     tp:approved-for-bedrock = true
                        │     tp:approved-for-athena  = true
                        │     tp:approved-for-s3      = true
                        │
                        ▼
              Single Role (TIP_ROLE_ARN)
              ┌────────────────────────────┐
              │ Inline Policy:             │
              │ ├─ Bedrock  → tag-gated   │
              │ ├─ Athena   → tag-gated   │
              │ └─ S3       → tag-gated   │
              └────────────────────────────┘
                        │
                        ▼
              Session credentials with tags
              ┌────────────────────────────┐
              │ aws:PrincipalTag/          │
              │   tp:approved-for-bedrock │
              │   tp:approved-for-athena  │
              │   tp:approved-for-s3      │
              └────────────────────────────┘
                        │
                        ▼
              Service API calls (Bedrock, Athena, S3)
              ┌────────────────────────────┐
              │ IAM evaluates condition:   │
              │   aws:PrincipalTag matches?│
              │     Yes → ALLOW            │
              │     No  → DENY (implicit)  │
              └────────────────────────────┘
```

## AWS Documentation

This pattern is documented by AWS in two places:

1. **[aws:PrincipalTag Condition Key](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-principaltag)**
   — Compare tags attached to the principal (including session tags) against policy values.

2. **[Pass Session Tags in AWS STS](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html)**
   — How session tags are injected during role assumption via `AssumeRole`, `AssumeRoleWithSAML`, or OIDC federation.

## Files in This Directory

| File | Description |
|---|---|
| `trust-policy.json` | Role trust policy — allows SSO to assume the role and pass session tags |
| `inline-policy.json` | Tag-gated inline policy — Bedrock, Athena, S3, and Glue permissions |
| `cloudformation.yml` | Older tag-gated carrier role design (does not match the live roles) |
| `agentcore-tip-identity-stack.yml` | Single CloudFormation stack: OIDC bootstrap role, enhanced (carrier) role, PEP base role |
| `agentcore-tip-identity/` | Terraform equivalent of `agentcore-tip-identity-stack.yml` |

> `TIP_ROLE_ARN` is the **carrier** role. The PEP also uses an OIDC bootstrap role (`OIDC_ROLE_ARN`) and a PEP base role (Fargate task role) that assumes the carrier role. See [docs/pep-base-identity.md](../docs/pep-base-identity.md#3-roles-reference) for all roles, trust requirements and the credential flow.

## Configuration

### 1. Apply the Trust Policy

Attach `trust-policy.json` as the role's trust relationship:

```bash
aws iam put-role-trust-policy \
    --role-name <CARRIER_ROLE_NAME> \
    --policy-document file://trust-policy.json
```

> The `sts:TagSession` action is required — without it, any session tag injection will fail.

### 2. Apply the Inline Policy

Attach `inline-policy.json` as an inline policy on the role:

```bash
aws iam put-role-policy \
    --role-name <CARRIER_ROLE_NAME> \
    --policy-name tip-session-tag-capabilities \
    --policy-document file://inline-policy.json
```

### 3. TIP Session Tags (OIDC Flattened Format)

For Entra ID (which doesn't support nested JSON in JWT claims), use the **flattened claim format**:

```json
{
  "https://aws.amazon.com/tags/principal_tags/tp:approved-for-bedrock": "true",
  "https://aws.amazon.com/tags/principal_tags/tp:approved-for-athena": "true",
  "https://aws.amazon.com/tags/principal_tags/tp:approved-for-s3": "true",
  "https://aws.amazon.com/tags/transitive_tag_keys": ["tp:approved-for-bedrock"]
}
```

> **Note:** `transitive_tag_keys` ensures the tag persists across role chaining if your architecture assumes additional roles downstream.

## How It Works

### Session Tag Inheritance

Session tags come from three sources (per AWS docs):

| Source | Description |
|--------|-------------|
| **Session tags**     | Tags passed when assuming the role via TIP|
| **Transitive session tags** | Tags inherited from a previous session in a role chain |
| **IAM resource tags** | Tags attached to the IAM role itself |

If a transitive tag and a resource tag share the same key, the transitive tag **overrides** the resource tag.

### Policy Evaluation Flow

1. User authenticates via Entra ID with MFA
2. TIP evaluates the token and context
3. TIP calls `CreateTokenWithIAM`, passing session tags based on policy decisions
4. AWS STS issues credentials with `aws:PrincipalTag/*` values
5. Application uses credentials to call Bedrock/Athena/S3
6. IAM evaluates the role's inline policy — checks `aws:PrincipalTag/tp:approved-for-*`
7. If the tag exists and matches → **ALLOW**; if missing or mismatched → **DENY**

### Tag Naming Convention

| Convention | Example | Notes |
|---|---|---|
| `tp:*` | `tp:approved-for-bedrock` | Short for "Token Protection" |
| Any custom prefix | `vt:ai-access`, `cihi:clearance` | Avoid `aws:` (reserved by AWS) |

## Key Constraints (from AWS documentation)

- Maximum **50 session tags** per session
- Tag keys ≤ **128 characters** (plaintext)
- Tag values ≤ **256 characters** (plaintext)
- Session tags are **single-valued** (no arrays per tag)
- Tags are valid only for the **current session** (expire with credentials)
- The `sts:TagSession` permission must be in the role trust policy — otherwise `AssumeRole` fails

## Benefits

- **One role** manages all service access — simpler IAM management
- **Dynamic control** — TIP decides per-session which capabilities are granted
