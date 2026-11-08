# Athena / Lake Formation MFA test

This example starts a local AgentCore-compatible AgentCore-TIP-MCP-Broker PEP server and invokes
Athena through Lake Formation trusted identity propagation.

## 1. Configure environment variables

All env vars are documented in the source — no `VERTICALTRUST_` prefix is used.

PowerShell:

```powershell
$env:AWS_REGION = "us-east-1"
$env:SSO_CLIENT_ID = "<identity-center-token-exchange-application-client-id-or-arn>"
$env:TIP_ROLE_ARN = "<final-lake-formation-tip-role-arn>"

# Optional, if your architecture uses an intermediary OIDC role before CreateTokenWithIAM.
$env:OIDC_ROLE_ARN = "<intermediary-oidc-role-arn>"
```

Or load from `.env`:

```powershell
Get-Content ..\.env | ForEach-Object {
    if ($_ -match '^#|^\s*$') { return }
    $key, $value = $_ -split '=', 2
    [System.Environment]::SetEnvironmentVariable($key, $value, 'Process')
}
```

Server-side env vars:

| Env var | Default | Description |
| --- | --- | --- |
| `SSO_CLIENT_ID` | *(required)* | Identity Center token exchange application ARN |
| `TIP_ROLE_ARN` | *(required)* | Final TIP role for Lake Formation access |
| `OIDC_ROLE_ARN` | — | Optional intermediary OIDC role |
| `CONFIG_FILE` | — | Path to JSON config (alternative to env vars) |
| `ATHENA_WORKGROUP` | `idc-wg` | Athena workgroup |
| `ATHENA_DATABASE` | `lfdb` | Athena database |
| `ATHENA_OUTPUT_LOCATION` | — | S3 prefix for query results |
| `PEP_ENCRYPTION_KEY` | — | Fernet key for session encryption (required with Redis) |
| `REDIS_URL` | — | Redis URL for session persistence (`rediss://` required) |

Client-side env vars:

| Env var | Default | Description |
| --- | --- | --- |
| `AGENT_URL` | `http://127.0.0.1:8080/invocations` | Agent server URL |
| `IDP` | `entra-id` | Identity provider (`entra-id` / `okta` / `cognito`) |
| `OIDC_CLIENT_ID` | *(required)* | Public/native OIDC client ID |
| `OIDC_DISCOVERY_URL` | — | OIDC discovery URL (auto-derived from `ENTRA_TENANT_ID`) |
| `OIDC_REDIRECT_URI` | `http://127.0.0.1:8765/callback` | Loopback redirect URI |
| `OIDC_SCOPES` | `openid profile email` | OIDC scopes |
| `OIDC_PROMPT` | `login` | OIDC prompt |
| `OIDC_TIMEOUT_SECONDS` | `300` | Browser login timeout |
| `USER_TOKEN` | — | Pre-existing JWT (skips browser login) |
| `USER_ID` | `mfa-test-user` | End-user identifier |

## 2. Run the PEP server locally

```powershell
python -m agentcore_tip.core.pep_server   # Plane A (/sessions) on 8080, Plane B (/mcp) on 8081
```

Or run the container:

```powershell
docker compose up --build
```

## 3. Invoke with automatic browser MFA

The client supports **Entra ID** (Microsoft/Azure AD), **Okta**, and **Cognito**
(hosted UI). Pick one with `--idp` or `IDP`. Configure a public/native OIDC
client with a loopback redirect URI such as:

```text
http://127.0.0.1:8765/callback
```

### Entra ID (Microsoft / Azure AD)

```powershell
$env:IDP = "entra-id"
$env:ENTRA_TENANT_ID = "<tenant-id>"
$env:OIDC_CLIENT_ID = "<entra-native-public-client-id>"
$env:OIDC_REDIRECT_URI = "http://127.0.0.1:8765/callback"

agentcore-tip-client --user-id "alice@example.com"
```

`OIDC_DISCOVERY_URL` is auto-derived from `ENTRA_TENANT_ID`, but you can set it explicitly:

```powershell
$env:OIDC_DISCOVERY_URL = "https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration"
```

### Okta

```powershell
$env:IDP = "okta"
$env:OKTA_URL = "https://dev-12345678.okta.com/oauth2/default"
$env:OIDC_CLIENT_ID = "<okta-native-public-client-id>"
$env:OIDC_REDIRECT_URI = "http://127.0.0.1:8765/callback"

agentcore-tip-client --user-id "alice@example.com"
```

No discovery document lookup — endpoints are derived as `<okta_url>/v1/authorize` and
`<okta_url>/v1/token`.

### Cognito (hosted UI)

```powershell
$env:IDP = "cognito"
$env:COGNITO_DOMAIN = "https://your-domain.auth.us-east-1.amazoncognito.com"
$env:OIDC_CLIENT_ID = "<cognito-app-client-id>"
$env:OIDC_REDIRECT_URI = "http://127.0.0.1:8765/callback"

agentcore-tip-client --user-id "alice@example.com"
```

Endpoints are derived as `<cognito_domain>/oauth2/authorize` and
`<cognito_domain>/oauth2/token`.

Regardless of provider, the client opens the browser, your IdP enforces MFA,
the client captures the authorization callback locally, and then it invokes:

```sql
SELECT * FROM "lfdb"."clients" LIMIT 10
```

against Athena workgroup `idc-wg`.

If you already have a post-MFA JWT, skip browser login:

```powershell
agentcore-tip-client --no-browser-login --user-id "alice@example.com"
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
