# PEP Identity Stack — `NoCredentialsError` Analysis, Role Design and Rollout

## 1. Symptom

Local run (agent container assumes a role, LLM on a local rig). `POST /sessions/init` succeeds, but every Plane B tool call (`list_tables`, `query_lake_formation`) logs:

```
ERROR agentcore_tip.core.plane_b_mcp: Downscoped role assumption failed
  ... sso_oidc.py, in _assume_role
  ... botocore/auth.py, in add_auth
    raise NoCredentialsError()
botocore.exceptions.NoCredentialsError: Unable to locate credentials
```

The HTTP response is still `200 OK` because the tool handler catches the exception and returns a tool error payload.

## 2. Root cause

The PEP container has **no AWS credentials of its own**. Plane B signs `sts:AssumeRole` (SigV4) with the ambient credential chain, and the chain is empty. It is an identity gap, not a logic bug and not an IAM denial (a denial would be an `AccessDenied` `ClientError`).

| | Plane A (`/sessions/init`) | Plane B (tool calls) |
|---|---|---|
| Strategy built in | `plane_a_ingest._build_strategy` | `plane_b_mcp._build_strategy` |
| `intermediary_role_arn` | set (`OIDC_ROLE_ARN`) | not set |
| STS call | unsigned `AssumeRoleWithWebIdentity` with the user's JWT, then `CreateTokenWithIAM` with those temporary credentials | signed `AssumeRole` of the carrier role |
| Needs ambient credentials | No | **Yes** |

Failure path: `_vend_credentials` → `assume_downscoped_role` (no `session`, so `boto3.Session(region_name=...)`) → `_assume_role` → `sts.assume_role(...)` → signing fails. The docstring states the design: "`session` defaults to the ambient credential chain (the PEP task role)". In Fargate the task role supplies it; in the local container nothing does.

Unrelated to the agent's role or the LLM; affects every Plane B tool.

## 3. Roles reference

Four identities are involved; only the OIDC role and the carrier role are *assumed* by the PEP flow, and the PEP base role is the identity that signs the carrier call.

| Identity | Config key | Used by | How obtained | Purpose |
|---|---|---|---|---|
| **OIDC (bootstrap) role** | `OIDC_ROLE_ARN` | Plane A | Unsigned `sts:AssumeRoleWithWebIdentity` with the IDP JWT | Its credentials only call `sso-oauth:CreateTokenWithIAM` to get the user's Identity Center context assertion and user id. No data access. |
| **Enhanced (carrier / TIP) role** | `TIP_ROLE_ARN` | Plane B | Signed `sts:AssumeRole` with `ProvidedContexts` (user assertion), `SourceIdentity` (agent role) and an inline session policy | Carries the data access (Lake Formation, Athena, Redshift Serverless, S3 Access Grants, optional Bedrock). The session policy narrows it to the tables in the validated SQL; Lake Formation applies the user's own grants. |
| **PEP base role** | none (it is the task role) | Plane B | ECS task role on Fargate; injected temporary credentials locally | Signs the carrier `AssumeRole`. Can assume the carrier role and nothing else. |
| **Agent role** | caller ARN header `x-amzn-caller-arn`, or `x-pep-agent-role-arn` when the caller is a trusted proxy (`PEP_TRUSTED_PROXY_ROLES`); allow-list `PEP_ALLOWED_AGENT_ROLES` | AgentCore / agent container | Not assumed by the PEP | Identifies who is calling. Must be in the carrier role's account. Becomes the STS `SourceIdentity` and owns the `session_ref` on first use. No PEP credentials, no data access. |

```
Plane A   user IDP JWT ──(unsigned AssumeRoleWithWebIdentity)──► OIDC role session
          OIDC role session ──(CreateTokenWithIAM)──► Identity Center context assertion ──► stored behind session_ref

Plane B   agent role calls PEP with session_ref (caller ARN from header)
          PEP base role creds ──(signed AssumeRole + SetContext + SetSourceIdentity + inline policy)──► carrier session
          carrier session ──► Athena / Glue / Redshift Data API / S3 Access Grants (down-scoped, Lake Formation per user)
```

Notes:
- `SourceIdentity` must match `[\w+=,.@-]{2,64}`; the PEP rejects anything else before calling STS.
- Each carrier assumption lasts 900 s and uses the session name `pep-<base>-<uuid>`. `<base>` is the trusted proxy's role name when a proxy forwarded the agent, otherwise the `source_identity`; it is cut so the whole name fits 64 characters. The UUID is logged as `request_id` for CloudTrail correlation.
- In CloudTrail the agent is `sessionContext.sourceIdentity` and the user is `onBehalfOf.userId` on every event; the proxy is in the session name. See [pass-agent-identity-to-cloudtrail.md](./pass-agent-identity-to-cloudtrail.md).
- Plane B tools accept only the opaque `session_ref`, never raw IDP tokens or AWS keys.
- The PEP passes no session tags, so `sts:TagSession` is not required on the PEP → carrier hop.

## 4. Review existing roles

Before deploying, inspect the trust relationships, audiences, session duration, and attached policies on existing roles in your own AWS account. Keep identity-bootstrap permissions separate from data-plane permissions. Avoid copying account-specific principals, role names, or broad permissions into a new deployment.

## 5. Decision: one stack, three new roles

**Yes, a single stack makes sense** for these three roles:
- They are one trust chain and reference each other (carrier trusts the PEP role; PEP role may assume the carrier; the optional legacy path lets the OIDC role assume the carrier). One stack deploys, updates and deletes them consistently and avoids cross-stack export/import coupling.
- The one thing that should *not* be in the stack is the Entra OIDC provider; it is shared and is referenced by ARN.
- Circular dependencies are avoided by keeping the cross-role permissions in separate policy resources.

The stack **creates new roles** (default prefix `agentcore-tip`) rather than editing existing shared roles. The new carrier role is deliberately narrow: **Lake Formation, Athena, Redshift Serverless, S3 Access Grants, and optional Bedrock** — nothing else.

| Item | Source |
|---|---|
| CloudFormation | [`iam/agentcore-tip-identity-stack.yml`](../iam/agentcore-tip-identity-stack.yml) (passes `cfn-lint` and `aws cloudformation validate-template`) |
| Terraform | [`iam/agentcore-tip-identity/`](../iam/agentcore-tip-identity) — `main.tf`, `variables.tf`, `outputs.tf` (passes `terraform fmt` and `terraform validate` 1.9; one deprecation warning for `data.aws_region.current.name` on provider v6) |

Neither has been deployed.

### Parameters

| Parameter (CFT / TF) | Default | Purpose |
|---|---|---|
| `NamePrefix` / `name_prefix` | `agentcore-tip` | Roles: `<prefix>-OIDCRole`, `<prefix>-IdEnhancedRole`, `<prefix>-PepServiceRole` |
| `OidcProviderArn` / `oidc_provider_arn` | required | Existing Entra OIDC provider ARN (referenced, not created) |
| `OidcAudiences` / `oidc_audiences` | required | Accepted token audiences (client ids) |
| `AthenaWorkGroup` / `athena_workgroup` | `idc-wg` | Must match PEP `ATHENA_WORKGROUP` |
| `AthenaResultsBucketName` / `athena_results_bucket_name` | empty | Adds S3 permissions for results only if the caller writes them |
| `RedshiftWorkgroupName` / `redshift_workgroup_name` | `*` | Scopes `ExecuteStatement` |
| `EnableBedrock` / `enable_bedrock`, `BedrockModelId` / `bedrock_model_id` | `false`, `amazon.nova-lite-v1:0` | Optional Bedrock invoke on one model |
| `AllowOidcRoleToAssumeCarrier` / `allow_oidc_role_to_assume_carrier` | `false` | Legacy `exchange()` path only; the PEP does not need it |
| `TrustEcsTasks` / `trust_ecs_tasks` | `true` | Fargate task role trust (same-account) |
| `LocalDevPrincipalArns` / `local_dev_principal_arns`, `LocalDevRequireMfa` / `local_dev_require_mfa` | empty, `false` | Who may assume the PEP base role for local runs |

Outputs: `OidcRoleArn` → `OIDC_ROLE_ARN`, `EnhancedRoleArn` → `TIP_ROLE_ARN`, `PepServiceRoleArn` → Fargate `taskRoleArn` / local assume-role target.

### Permissions in the new carrier role

| Area | Allowed |
|---|---|
| Lake Formation | `lakeformation:GetDataAccess` (no resource-level scoping; LF enforces the user's grants) |
| Athena | Start/Get/Stop/GetQueryResults(+Stream)/GetWorkGroup on the one workgroup; List catalogs/databases/workgroups |
| Glue catalog | Read-only get/list on catalog, databases, tables |
| S3 results | Optional, only on the configured bucket |
| S3 Access Grants | `GetAccessGrantsInstanceForPrefix` on the default instance; `GetDataAccess`, `ListCallerAccessGrants` |
| Redshift Serverless | `ExecuteStatement`/`BatchExecuteStatement` on the workgroup; statement describe/get/list actions |
| Bedrock | Optional `InvokeModel*` on one model |

It is a superset of the actions the PEP's session policy grants (`sql_guard.generate_downscoped_policy`), which is required because the effective permissions are the intersection of the two.

### Deliberately dropped (vs. the live enhanced role)

Glue interactive sessions, EMR / EMR Serverless, JupyterHub callers, `iam:PassRole`/`GetRole`, Identity Store / `ListAccountAliases`, CloudTrail lookup, Lambda/Athena helpers, S3 Access Grants administration (`ListAccessGrants*`, locations), `ListAllMyBuckets`/`ListBucket` on `*`, the deployment bucket, `sso-oidc:CreateTokenWithIAM`, Glue/SageMaker service trust, `sts:TagSession`, `sso:DescribeApplication` (the PEP code never calls it), and the 12 h max session (now 1 h).

### Assumptions to confirm

1. `lakeformation:GetDataAccess` is **added** (the live role does not have it, but the PEP session policy and Athena-over-Lake-Formation use it). Remove it if your IAM Identity Center workgroup does not need it.
2. Redshift Serverless via the Data API needs only the `redshift-data` actions listed; `redshift-serverless:GetCredentials` is not included.
3. S3 Access Grants `GetDataAccess` / `ListCallerAccessGrants` are on `*` (as on the live role); the instance-level action is scoped to the default instance.
4. Bedrock is off by default; AgentCore runtime permissions are not included.
5. The OIDC role keeps the live trust shape (`AssumeRoleWithWebIdentity`, `TagSession`, `SetSourceIdentity`, audience condition) and a 1 h max session, which matches the 3600 s the strategy requests.

## 6. Repository state

| Item | State |
|---|---|
| [`iam/agentcore-tip-identity-stack.yml`](../iam/agentcore-tip-identity-stack.yml), [`iam/agentcore-tip-identity/`](../iam/agentcore-tip-identity) | New: the three-role stack (CFT and Terraform) |
| [`iam/cloudformation.yml`](../iam/cloudformation.yml), [`iam/main.tf`](../iam/main.tf), [`iam/trust-policy.json`](../iam/trust-policy.json), [`iam/inline-policy.json`](../iam/inline-policy.json) | Older tag-gated design (`tp:approved-for-*`, SSO-only trust). It does not match the live roles and is not used by the stack above; unchanged |
| Fargate CloudFormation/Terraform | **Not in this repo** — no ECS cluster, task definition or task role. Fargate is described only in [`pep_api_contract.md`](../pep_api_contract.md) and the docs |

## 7. Implementation tasks

1. **Deploy the stack** (CFT or Terraform) with the existing Entra provider ARN and audiences, and `local_dev_principal_arns` set to the developer identity for local runs.
2. **Point the PEP at the new roles:** `OIDC_ROLE_ARN` = `OidcRoleArn`, `TIP_ROLE_ARN` = `EnhancedRoleArn`. Check `ATHENA_WORKGROUP` and, if the caller writes results, `ATHENA_OUTPUT_LOCATION` (and `AthenaResultsBucketName`).
3. **Fargate:** set the task definition's `taskRoleArn` (not the execution role) to `PepServiceRoleArn`.
4. **Local container:** assume the PEP base role and inject the temporary credentials:
   ```
   aws sts assume-role --role-arn <PepServiceRoleArn> --role-session-name pep-local
   ```
   then set `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` in the PEP container (or mount a profile that assumes the role). Chained sessions last at most 1 hour.
5. **Optional:** add the PEP's `PEP_ALLOWED_AGENT_ROLES` for the agent roles.
6. No PEP code change is needed.

## 8. Verification

Inside the PEP container:

```
python -c "import boto3;print(boto3.client('sts').get_caller_identity())"
```

It should show the assumed PEP base role. Then:

1. `POST /sessions/init` → 200.
2. `list_tables` returns tables and the log shows `Assumed carrier role: agent=... request_id=...`.
3. CloudTrail shows an `AssumeRole` on the new enhanced role by the PEP base role, with `SourceIdentity` set and a session name containing the `request_id`.

| Error | Meaning |
|---|---|
| `NoCredentialsError` | The container still has no ambient credentials |
| `AccessDenied` on `AssumeRole` | `TIP_ROLE_ARN` still points at the old role (which does not trust the PEP role), or the PEP role policy / carrier trust is wrong |
| `AccessDenied` in Athena / Glue / Redshift / S3 | The carrier role lacks an action the session policy allows, or Lake Formation / S3 Access Grants does not grant the user |
