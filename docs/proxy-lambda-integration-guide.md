# Proxy Lambda integration guide

Audience: the team that builds the **proxy Lambda** (between the agent and Plane B) and the **agent application** that calls it.
Everything here is what the PEP (Plane B) expects from its caller. Plane B itself is documented in [pep_api_contract.md](../pep_api_contract.md); read §3 there for tools, arguments and errors. This guide covers only what is specific to calling Plane B through a proxy behind a private API Gateway.

```
user --prompt + session_ref--> Agent (AgentCore Runtime)
Agent --lambda:Invoke (IAM)--> Proxy Lambda
Proxy Lambda --SigV4 (execute-api) + x-pep-agent-role-arn--> Private API Gateway (VPC endpoint, IAM auth)
  --x-amzn-caller-arn = context.identity.userArn--> VPC link --> NLB --> PEP Plane B :8081
```

## 1. What the proxy must do

1. Authenticate **the agent** (who invoked the Lambda) from AWS-verified information, never from the request body.
2. Call Plane B through the private API with **SigV4** (service `execute-api`) using the Lambda's own execution role.
3. Send the agent's role in the **`x-pep-agent-role-arn`** header on every call.
4. Pass the tool payload through unchanged. The Lambda never sees or handles IdP tokens, Identity Center assertions or AWS keys; only the opaque `session_ref`.
5. Return Plane B's JSON to the agent, preserving the HTTP status.

## 2. Why the agent header exists

API Gateway verifies the **Lambda** (it maps the verified caller to `x-amzn-caller-arn`). Without more information Plane B would see only the proxy, so every agent would look the same: CloudTrail would show the proxy, and any agent could use another agent's `session_ref`.

When the verified caller is listed in `PEP_TRUSTED_PROXY_ROLES`, Plane B takes the real caller from `x-pep-agent-role-arn` instead. Plane B then:

- checks that agent role against `PEP_ALLOWED_AGENT_ROLES` and the carrier account;
- binds the `session_ref` to that agent;
- uses the agent as the STS `SourceIdentity`, so CloudTrail shows `sourceIdentity = <agent>`, `onBehalfOf.userId = <user>`, and the proxy in the session name (`pep-<proxy>-<uuid>`).

| Header | Set by | Value |
|---|---|---|
| `x-amzn-caller-arn` | API Gateway (from the SigV4 signature). The Lambda never sets it in production. | the proxy's assumed-role ARN |
| `x-pep-agent-role-arn` | the proxy Lambda | the agent's role ARN (assumed-role or role ARN, see §3) |

Plane B returns `401` if the trusted proxy omits the agent header, repeats it, or sends something that is not a valid role ARN, and `403` if that agent is not allowed. It ignores the header for any other caller.

## 3. Where the agent identity comes from

The agent role must come from something the agent cannot forge. A direct `lambda:Invoke` gives the function **no caller identity** (`context.identity` is only for Cognito and mobile), so choose one:

| Option | How the Lambda learns the agent | Use when |
|---|---|---|
| **One Lambda per agent role** (or alias with its own env var) | a configured constant (`AGENT_ROLE_ARN`), with the Lambda's resource policy allowing `lambda:InvokeFunction` only from that role | a small, fixed set of agents. Simple and verifiable. |
| **IAM-authenticated front door** (Function URL with `AWS_IAM`, or API Gateway) in front of the Lambda | `event["requestContext"]["authorizer"]["iam"]["userArn"]` (Function URL / HTTP API) or `requestContext.identity.userArn` (REST API) | several agents share one Lambda. A Function URL is a public endpoint protected by IAM, so check that fits your network policy. |
| **Agent supplies its own role in the payload** | not acceptable | never. Any invoker could claim any role. |

Send the value as received. An assumed-role ARN (`arn:aws:sts::<acct>:assumed-role/<Role>/<session>`) is accepted as-is; Plane B uses the role name and account.

Also: drop every incoming header and body field whose name starts with `x-pep-` or equals `x-amzn-caller-arn`, and set `x-pep-agent-role-arn` only from the verified source.

## 4. Calling Plane B

- **URL:** `PLANE_B_URL` is the private API invoke URL including the stage, then `/mcp/tools/{tool}/call` (or `/mcp` for JSON-RPC). The stage prefix must line up with Plane B's `/mcp/...` routes.
- **Signing:** SigV4 with service name `execute-api`, the Lambda's credentials (including the session token) and the API's region. API Gateway supports normal payload signing.
- **Timeout:** use at least 120 s on the HTTP client and the Lambda. Athena can run 90 s (`ATHENA_TIMEOUT_SECONDS`).
- **Retries:** retry `429`, `502` and `Athena/Glue request failed` with backoff and jitter. Do not retry `401`, `403`, `413`, `422` or any `ok:false` validation error unchanged.
- **Always check `ok`:** tool errors come back as HTTP 200 with `"ok": false`.

### Example (Python, standard library plus boto3; `requests` is not in the Lambda runtime)

```python
import json
import os
import urllib.error
import urllib.request

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

PLANE_B_URL = os.environ["PLANE_B_URL"].rstrip("/")  # https://<api>.execute-api.<region>.amazonaws.com/<stage>
REGION = os.environ["AWS_REGION"]
AGENT_HEADER = "x-pep-agent-role-arn"


def _agent_role_arn(event: dict) -> str:
    # Choose ONE source from §3. This one is for a Function URL / HTTP API with IAM auth.
    arn = ((event.get("requestContext") or {}).get("authorizer") or {}).get("iam", {}).get("userArn")
    if not arn:
        raise PermissionError("caller identity is not available")
    return arn
    # One Lambda per agent role: return os.environ["AGENT_ROLE_ARN"] instead.


def call_plane_b(tool: str, body: dict, agent_role_arn: str) -> tuple[int, dict]:
    url = f"{PLANE_B_URL}/mcp/tools/{tool}/call"
    data = json.dumps(body).encode()
    request = AWSRequest(
        method="POST",
        url=url,
        data=data,
        headers={"Content-Type": "application/json", AGENT_HEADER: agent_role_arn},
    )
    credentials = boto3.Session().get_credentials().get_frozen_credentials()  # the Lambda's own role
    SigV4Auth(credentials, "execute-api", REGION).add_auth(request)
    http_request = urllib.request.Request(url, data=data, headers=dict(request.headers.items()), method="POST")
    try:
        with urllib.request.urlopen(http_request, timeout=120) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as err:  # 401 / 403 / 413 / 429 from API Gateway or Plane B
        return err.code, json.loads(err.read() or b"{}")


def lambda_handler(event, context):
    agent = _agent_role_arn(event)
    payload = json.loads(event.get("body") or "{}")
    payload = payload.get("arguments", payload)
    tool = payload.pop("tool")  # example: how the tool name reaches the Lambda is up to your app
    status, result = call_plane_b(tool, payload, agent)
    return {"statusCode": status, "body": json.dumps(result)}
```

This is a starting point, not a drop-in: the request and response shapes between the agent and the Lambda are yours to define. Keep the identity handling (§3) and the signing as shown.

## 5. IAM and API Gateway settings

| Where | Setting |
|---|---|
| Lambda execution role | `execute-api:Invoke` on `arn:aws:execute-api:<region>:<account>:<api-id>/<stage>/POST/mcp/*` (and `GET/mcp/tools` if used) |
| Lambda resource policy / Function URL | invoke allowed only from the agent role(s) |
| API Gateway method auth | `AWS_IAM` on every Plane B method |
| API Gateway resource policy | `execute-api:Invoke` only from the VPC endpoint and only for the proxy Lambda's role |
| Integration request | `integration.request.header.x-amzn-caller-arn` = `context.identity.userArn`; pass `x-pep-agent-role-arn` through from the method request |
| Plane B security group | port 8081 admitted only from the NLB path |

The full API, VPC link and NLB build list is in [deployment-topologies.md](./deployment-topologies.md) (Topology B).

### Plane B settings the operator must set

| Setting | Value |
|---|---|
| `PEP_TRUSTED_PROXY_ROLES` | the proxy Lambda's role ARN (full IAM role ARN) |
| `PEP_ALLOWED_AGENT_ROLES` | the agent role ARN(s); empty allows any role in the carrier account |
| `PEP_CALLER_ARN_HEADER` | `x-amzn-caller-arn` (default) |
| `PEP_AGENT_ARN_HEADER` | `x-pep-agent-role-arn` (default) |

## 6. What you will see

| Situation | Result |
|---|---|
| Proxy calls with a valid agent header | `200`, normal tool result |
| Agent header missing, repeated or not a role ARN | `401 {"detail":"Missing or invalid agent identity."}` |
| Agent not allowed, or in another account | `403 {"detail":"Caller is not an authorized agent role."}` |
| Same `session_ref` used by a different agent | `200 {"ok": false, "error": "Session is bound to a different agent identity."}` |
| Unsigned call or a caller that is not the proxy | rejected by API Gateway, or treated as a direct caller by Plane B |
| Too many calls | `429`. The limit is **20/minute per source IP**; behind API Gateway the source IP is the VPC link, so callers share it. Ask the operator to raise `RATE_LIMIT_TOOL_CALLS` if needed. |

In CloudTrail, a query shows `sessionContext.sourceIdentity = <agent role name>`, `onBehalfOf.userId = <user>` and a session name `pep-<proxy role, cut to 27 chars>-<uuid>`. The UUID is logged by Plane B as `request_id`, so log your own request id next to the agent ARN to join the trail end to end. Sessions that existed before this was deployed were bound to the proxy role and stop working for agents until they expire.

## 7. Test checklist

1. **Happy path:** a query through the full chain returns rows, and CloudTrail shows the agent as `sourceIdentity`.
2. **Header overwrite:** send your own `x-amzn-caller-arn` through the API; Plane B must receive the mapped value. If the client value passes through, do not go to production.
3. **Direct agent header:** call the API as any principal other than the proxy; it must be rejected, so nobody else can claim an agent role.
4. **Missing agent header from the proxy:** returns `401`.
5. **Agent not on the allow-list:** returns `403`, and no AWS credentials are vended.
6. **Two agents, one `session_ref`:** the second agent gets `Session is bound to a different agent identity.`
7. **Long query:** the default API Gateway integration timeout is 29 s while Athena can run 90 s. Raise the limit if the quota allows, or confirm your longest query fits.
8. **No identity in the payload:** a request body with an `agent` or role field must not change who Plane B treats as the caller.

## 8. Do not

- Do not take the agent role from anything the agent controls.
- Do not log `session_ref`, SigV4 headers or credentials; log a hash of the `session_ref` if you need correlation.
- Do not call Plane B directly (bypassing API Gateway), and do not set `x-amzn-caller-arn` from the Lambda in production.
- Do not forward unknown headers from the agent to Plane B.
