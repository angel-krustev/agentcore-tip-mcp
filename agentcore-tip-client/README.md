# agentcore-tip-client

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

**Open-source OIDC client** for [AgentCore-TIP-MCP-Broker](https://github.com/angel-krustev/agentcore-tip-mcp) identity propagation.

- 🔐 **Browser login** — Interactive Microsoft Entra ID (or other IdP) login with PKCE
- 🔧 **Agent invocation** — Invoke AgentCore-TIP-MCP-Broker agents with post-MFA tokens
- 🚀 **Zero dependencies** — Pure Python, no Cython/compiled extensions
- 📦 **Pip installable** — Works on Windows, macOS, and Linux

## Quick Start

```bash
pip install agentcore-tip-client
```

```bash
# Interactive login + query
agentcore-tip-client

# Skip browser, paste token manually
agentcore-tip-client --no-browser-login

# Use a token directly
agentcore-tip-client --token "<POST_MFA_JWT>"
```

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `AGENT_URL` | Agent server URL | `http://127.0.0.1:8080/invocations` |
| `USER_TOKEN` | Post-MFA JWT (skips login) | *(empty)* |
| `IDP` | Identity provider (`entra-id`, `okta`, `cognito`) | *(empty)* |
| `OIDC_DISCOVERY_URL` | OIDC discovery endpoint | *(empty)* |
| `OIDC_CLIENT_ID` | OIDC client/app ID | *(empty)* |
| `OIDC_REDIRECT_URI` | Loopback redirect URI | *(empty)* |
| `OIDC_SCOPES` | OIDC scopes | *(empty)* |
| `OIDC_PROMPT` | OIDC prompt | `login` |
| `OIDC_TIMEOUT_SECONDS` | Login timeout (seconds) | `300` |
| `USER_ID` | End-user identifier | `mfa-test-user` |
| `SESSION_ID` | Session ID | *(auto-generated)* |

## Command-Line Reference

```
agentcore-tip-client
  --url <url>                Agent server URL
  --token <jwt>              Post-MFA JWT (skip login)
  --no-browser-login         Prompt for JWT instead of browser login
  --idp <provider>           Identity provider (entra-id, okta, cognito)
  --oidc-discovery-url <url> OIDC discovery URL
  --oidc-client-id <id>      OIDC client ID
  --oidc-redirect-uri <uri>  Redirect URI
  --oidc-scopes <scopes>     OIDC scopes
  --oidc-prompt <prompt>     OIDC prompt
  --oidc-timeout-seconds <s> Login timeout
  --user-id <id>             User identifier
  --session-id <id>          Session ID
  --database <name>          Athena database
  --table <name>             Athena table
  --workgroup <name>         Athena workgroup
  --limit <n>                Result limit
  --query <sql>              Explicit SQL query
```

## Python API

```python
from agentcore_tip_client import interactive_login, AgentCoreTIPClient

# Interactive browser login
token = interactive_login(idp="entra-id")

# Or use a pre-existing token directly
client = AgentCoreTIPClient(url="http://127.0.0.1:8080/invocations")
result = client.invoke(
    token=token,
    payload={"query": "SELECT * FROM my_table LIMIT 5"},
    user_id="alice",
)
print(result.data)
```

## Architecture

```
┌──────────────┐  Interactive Login   ┌──────────────┐
│   Browser    │ ────────────────────>│     IdP      │
│  (PKCE)      │  <────────────────── │  (Entra ID)  │
└──────────────┘   POST /callback     └──────────────┘
                                 │
                                 │ JWT Token
                                 ▼
┌──────────────┐      JWT + Payload  ┌──────────────┐
│  agentcore-tip-client   │ ──────────────────> │   Agent      │
│  (this pkg)  │  <────────────────── │  Server      │
└──────────────┘      Query Results  └──────────────┘
```

## Development

```bash
git clone https://github.com/angel-krustev/agentcore-tip-mcp.git
cd agentcore-tip-client
pip install -e .
agentcore-tip-client --help
```

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.
