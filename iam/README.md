# AgentCore TIP IAM Identity Stack

This directory contains the IAM role definitions for the PEP identity flow. The design uses three roles:

1. **OIDC bootstrap role** (`OIDC_ROLE_ARN`): assumed with the user's IDP token and used to call `sso-oauth:CreateTokenWithIAM`.
2. **Enhanced carrier role** (`TIP_ROLE_ARN`): assumed by the PEP base role to access permitted data services. Bedrock model invocation is optional and disabled by default.
3. **PEP base role**: the Fargate task role, or a role assumed for local runs. It signs the call to assume the carrier role and has no data permissions of its own.

The PEP passes an Identity Center context and source identity when assuming the carrier role. It does **not** pass session tags. See [the PEP identity documentation](../docs/pep-base-identity.md) for the trust chain, permissions, configuration, and rollout steps.

## Stack definitions

| File | Description |
|---|---|
| [agentcore-tip-identity-stack.yml](agentcore-tip-identity-stack.yml) | CloudFormation stack defining the OIDC bootstrap, carrier, and PEP base roles |
| [agentcore-tip-identity/](agentcore-tip-identity/) | Terraform equivalent |

The stack templates have not been deployed. Review the existing IAM roles and configure the required parameters for your AWS account before deployment.

## Bedrock access

The carrier role can optionally receive `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream` for one configured foundation model. Enable this with `EnableBedrock` (CloudFormation) or `enable_bedrock` (Terraform); it is disabled by default.
