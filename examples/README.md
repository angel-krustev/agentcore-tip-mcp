# Athena / Lake Formation MFA test

This example starts a local AgentCore-compatible AgentCore-TIP-MCP-Broker agent and invokes
Athena through Lake Formation trusted identity propagation.

## 1. Configure the agent

PowerShell:

```powershell
$env:AWS_REGION = "us-east-1"
$env:VERTICALTRUST_SSO_CLIENT_ID = "<identity-center-token-exchange-application-client-id-or-arn>"
$env:VERTICALTRUST_TIP_ROLE_ARN = "<final-lake-formation-tip-role-arn>"

# Optional, if your architecture uses an intermediary OIDC role before CreateTokenWithIAM.
$env:VERTICALTRUST_OIDC_ROLE_ARN = "<intermediary-oidc-role-arn>"
```

If you already have an `aws-oidc-tip` JSON config, you can use it directly:

```powershell
$env:VERTICALTRUST_CONFIG_FILE = "C:\path\to\aws-oidc-tip-config.json"
```

Field mapping:

| aws-oidc-tip config field | AgentCoreTIP use |
| --- | --- |
| `token_exchange_application_arn` | Agent-side `CreateTokenWithIAM` client ID/application ARN |
| `oidc_role_arn` | Optional intermediary `AssumeRoleWithWebIdentity` role |
| `id_enhanced_role_arn` | Final TIP role used with STS `ProvidedContexts` |
| `region` | AWS region |
| `session_duration_seconds` | Exchanged credential duration |
| `entra_tenant_id` | Builds Entra discovery URL |
| `entra_client_id` | Browser MFA public/native OIDC client ID |

## 2. Run the agent locally

```powershell
$env:PYTHONPATH = "C:\Users\angel\projects\AgentCore-TIP-MCP-Broker"
python -m uvicorn agents.athena_lf_agent:app --host 0.0.0.0 --port 8080
```

Or run the container:

```powershell
docker compose up --build
```

## 3. Invoke with automatic browser MFA

AgentCoreTIP supports the same identity providers as `aws-oidc-tip`'s
`cihi_auth.auth` package: **Entra ID** (Microsoft/Azure AD), **Okta**, and
**Cognito** (hosted UI). Pick one with `--idp` / `VERTICALTRUST_IDP`, or let
it fall back to the `idp` field already present in your `aws-oidc-tip` config
file. Configure a public/native OIDC client with a loopback redirect URI such
as:

```text
http://127.0.0.1:8765/callback
```

### Entra ID (Microsoft / Azure AD)

```powershell
$env:PYTHONPATH = "C:\Users\angel\projects\AgentCore-TIP-MCP-Broker"
$env:VERTICALTRUST_IDP = "entra-id"
$env:VERTICALTRUST_OIDC_DISCOVERY_URL = "https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration"
$env:VERTICALTRUST_OIDC_CLIENT_ID = "<entra-native-public-client-id>"
$env:VERTICALTRUST_OIDC_REDIRECT_URI = "http://127.0.0.1:8765/callback"

python -m examples.mfa_athena_client --user-id "alice@example.com"
```

For your `aws-oidc-tip` config, `VERTICALTRUST_OIDC_CLIENT_ID` is the
`entra_client_id` value, and `VERTICALTRUST_OIDC_DISCOVERY_URL` can be
omitted if `entra_tenant_id` is present in the config file — the discovery
URL is derived from it automatically.

### Okta

```powershell
$env:PYTHONPATH = "C:\Users\angel\projects\AgentCore-TIP-MCP-Broker"
$env:VERTICALTRUST_IDP = "okta"
$env:VERTICALTRUST_OKTA_URL = "https://dev-12345678.okta.com/oauth2/default"
$env:VERTICALTRUST_OIDC_CLIENT_ID = "<okta-native-public-client-id>"
$env:VERTICALTRUST_OIDC_REDIRECT_URI = "http://127.0.0.1:8765/callback"

python -m examples.mfa_athena_client --user-id "alice@example.com"
```

No discovery document lookup is used for Okta — the authorize/token
endpoints are derived directly as `<okta_url>/v1/authorize` and
`<okta_url>/v1/token`, matching `cihi_auth.auth.okta_auth.OktaAuth`.

### Cognito (hosted UI)

```powershell
$env:PYTHONPATH = "C:\Users\angel\projects\AgentCore-TIP-MCP-Broker"
$env:VERTICALTRUST_IDP = "cognito"
$env:VERTICALTRUST_COGNITO_DOMAIN = "https://your-domain.auth.us-east-1.amazoncognito.com"
$env:VERTICALTRUST_OIDC_CLIENT_ID = "<cognito-app-client-id>"
$env:VERTICALTRUST_OIDC_REDIRECT_URI = "http://127.0.0.1:8765/callback"

python -m examples.mfa_athena_client --user-id "alice@example.com"
```

The authorize/token endpoints are derived as `<cognito_domain>/oauth2/authorize`
and `<cognito_domain>/oauth2/token`, matching
`cihi_auth.auth.cognito_auth.CognitoAuth`.

### Config-file field mapping (all IdPs)

If `VERTICALTRUST_CONFIG_FILE` points at your `aws-oidc-tip` JSON config, the
provider and its settings are picked up automatically, including the file's
own `idp` field:

| aws-oidc-tip config field | AgentCoreTIP use |
| --- | --- |
| `idp` | Selects the provider (`entra-id` / `okta` / `cognito`) unless `--idp`/`VERTICALTRUST_IDP` overrides it |
| `entra_tenant_id` | Builds the Entra discovery URL |
| `entra_client_id` | Entra browser MFA public/native OIDC client ID |
| `okta_url` | Okta authorize/token base URL |
| `okta_client_id` | Okta browser MFA client ID (used if `VERTICALTRUST_OIDC_CLIENT_ID` is unset) |
| `cognito_domain` | Cognito hosted-UI authorize/token base URL |
| `cognito_client_id` | Cognito app client ID (used if `VERTICALTRUST_OIDC_CLIENT_ID` is unset) |

Regardless of provider, the client opens the browser, your IdP enforces MFA,
the client captures the authorization callback locally, and then it invokes:

```sql
SELECT * FROM "lfdb"."clients" LIMIT 10
```

against Athena workgroup `idc-wg`.

If you already have a post-MFA JWT, skip browser login:

```powershell
python -m examples.mfa_athena_client --no-browser-login --user-id "alice@example.com"
```

## 4. Test the Secure Broker / PEP with MFA

`examples/mfa_pep_client.py` exercises the dual-interface PEP: browser MFA login,
`POST /sessions/init` (returns only an opaque `session_ref`), then the Plane B tools
(`list_tables`, `describe_table`, `query_lake_formation`) with just `session_ref` + SQL.
The raw token is never printed and is dropped right after `/sessions/init`.

Start a local PEP (it needs ambient AWS credentials allowed to assume the TIP role):

```powershell
$env:SSO_CLIENT_ID = "<token-exchange-application-arn>"
$env:TIP_ROLE_ARN = "<final-lake-formation-tip-role-arn>"
$env:OIDC_ROLE_ARN = "<intermediary-oidc-role-arn>"
$env:ATHENA_OUTPUT_LOCATION = "s3://<results-bucket>/pep/"
python -m agentcore_tip.core.pep_server   # Plane A (/sessions) on 8080, Plane B (/mcp) on 8081
```

Run the client (Entra ID shown; Okta/Cognito use the same options as above):

```powershell
$env:PYTHONPATH = "C:\Users\angel\projects\AgentCore-TIP-MCP-Broker"
$env:ENTRA_TENANT_ID = "<tenant-id>"
$env:OIDC_CLIENT_ID = "<entra-native-public-client-id>"
python -m examples.mfa_pep_client --require-mfa --negative-checks
```

- `--require-mfa` checks the id_token's `amr` claim when the IdP provides it (it must contain `mfa`).
  If `amr` is absent or empty (common for Entra v2 tokens unless the optional claim is configured), the
  client notes it, treats it as empty and continues; MFA is then enforced only by your IdP policy.
- `--negative-checks` also confirms the PEP rejects a missing caller identity, an unknown
  `session_ref`, `DROP`/`INSERT`/stacked SQL, and that no LLM tools are exposed.
- Plane B authenticates the *agent*, not the user. Locally the client plays the agent by sending
  an `x-amzn-caller-arn` header (`--agent-role`, `--account-id`); that header is only trustworthy
  when the PEP is not exposed directly, so never use it against a deployed PEP. For a deployed PEP use
  `--sigv4` (signs with your local AWS credentials; `--sigv4-service` defaults to `vpc-lattice-svcs`)
  and point `--plane-b-url` (and `--plane-a-url`) at the deployed listeners.
- Plane A (`/sessions`, port 8080) and Plane B (`/mcp`, port 8081) are separate listeners; each port only
  serves its own routes. Expose 8080 to the user/VPN load balancer and 8081 only to the agent network.
- Use `--token` / `--no-browser-login` to supply an existing post-MFA JWT, and `--sql` for a custom query.
- The caller ARN is validated in full (partition, service, account, role name) and must be in the
  same account as the TIP role. `PEP_ALLOWED_AGENT_ROLES` (comma-separated) must list **full IAM role
  ARNs**, e.g. `arn:aws:iam::123456789012:role/FinancialAnalystAgentRole`; the PEP refuses to start
  otherwise. For the STS call to succeed, the TIP role's trust policy must permit `sts:SetSourceIdentity`.
- Each `session_ref` is bound to the first agent role that uses it (trust on first use); a different
  agent role presenting the same `session_ref` is rejected. Restart the client/login to get a new one.
  To exercise this check live, list a second role (default `IntruderAgentRole`, see `--other-agent-role`)
  in `PEP_ALLOWED_AGENT_ROLES`; otherwise the allow-list rejects it first (403) and the check reports SKIP.
- The Athena workgroup is fixed server-side (`ATHENA_WORKGROUP`); callers cannot choose it.
- **Session storage.** Without `REDIS_URL` sessions live in process memory (local development only). With
  `REDIS_URL`, the URL **must** start with `rediss://` (TLS) and keep certificate and hostname verification on:
  plaintext `redis://`, `unix://`, any other scheme, and `ssl_cert_reqs=none|optional` / `ssl_check_hostname=false`
  are refused at startup (the error never echoes the URL, which may contain the password). Trust a private CA with
  `rediss://host:6379/0?ssl_ca_certs=/path/ca.pem`. Every session record is also Fernet-encrypted before it is
  written, and `PEP_ENCRYPTION_KEY` is
  **required**: the PEP refuses to start without a valid key and never falls back to plaintext. Generate one with
  `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` and store it in
  Secrets Manager / SSM, not in the image. To rotate, set `PEP_ENCRYPTION_KEY=<new>,<old>` (the first key
  encrypts, all keys decrypt), then drop `<old>` after one session TTL (`CONTEXT_TTL_SECONDS`, default 3600).
- **Request size.** Both planes (and the LLM host) refuse bodies larger than `MAX_REQUEST_BODY_BYTES`
  (default 1 MiB) with `413`, counting the bytes actually streamed; `Content-Length` is never trusted.
- Validation errors (`422`) on both planes return only the field location and a fixed message, never the
  submitted values, so an IDP JWT cannot be echoed back. A `refresh_token` in the `/sessions/init` body is ignored.

The same flow is covered offline (no AWS, no browser) by `tests/test_pep_e2e.py`.
