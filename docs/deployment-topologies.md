# Deployment topologies: DEV/SBX and PROD

The PEP supports two deployment topologies. They differ only in how Plane B learns **which agent role is calling**. Plane A, the session store, the SQL guard and the credential down-scoping are identical in both.

| | DEV/SBX | PROD |
|---|---|---|
| Plane B caller verification | Header `x-amzn-caller-arn` set by the proxy Lambda, protected by network controls | Private API Gateway with IAM auth (SigV4), which sets the header from the verified caller |
| PEP code and image | Same | Same |
| Trust anchor | Security groups and IAM permissions | API Gateway signature verification and resource policy |
| Intended use | Development, sandbox, demos | Production |

See [gaps-zerotrust.md](../gaps-zerotrust.md) for the gap analysis that motivates the PROD topology (gaps 1 and 2).

## Common flow

1. The user signs in with the IdP (MFA enforced there) and calls Plane A: `POST /sessions/init` on port 8080 with the JWT.
2. The PEP validates the JWT, exchanges it for an Identity Center context, stores the session, and returns an opaque `session_ref`. No raw token leaves Plane A.
3. The user calls the agent (AgentCore Runtime). The agent holds only the `session_ref`.
4. The agent calls the proxy Lambda, which calls Plane B (`/mcp/tools/{tool}/call`, port 8081) with the `session_ref` and tool arguments.
5. Plane B verifies the caller. When the verified caller is a trusted proxy (`PEP_TRUSTED_PROXY_ROLES`), the agent role it forwards in `x-pep-agent-role-arn` is checked against `PEP_ALLOWED_AGENT_ROLES`; otherwise the caller itself is checked. It then resolves the `session_ref`, pins it to that agent (`bind_agent`), validates the SQL, down-scopes the credentials, and runs the query in Athena under Lake Formation. The STS `SourceIdentity` is the agent role.
6. The result returns through the same path to the user.

## Topology A: DEV/SBX

```
user --JWT--> PEP Plane A :8080 --> session_ref
user --prompt + session_ref--> Agent (AgentCore Runtime)
Agent --> Proxy Lambda --x-amzn-caller-arn (proxy) + x-pep-agent-role-arn (agent)--> PEP Plane B :8081 --> Lake Formation / Athena --> user
```

### How the caller is identified

- The proxy Lambda reads its own role from STS and sends it as `x-amzn-caller-arn`.
- Plane B parses the ARN and requires the same account as the carrier role.
- If the proxy is listed in `PEP_TRUSTED_PROXY_ROLES`, the Lambda also sends the **calling agent's** role in `x-pep-agent-role-arn`, taken from an identity the agent cannot forge. Plane B then treats that agent role as the caller: it must be in the carrier account and on `PEP_ALLOWED_AGENT_ROLES`, and it owns the `session_ref` and becomes the STS `SourceIdentity`. The proxy role stays visible in the STS session name (`pep-<proxy>-<uuid>`). A missing, repeated or malformed agent header from the proxy returns 401; the header is ignored for every other caller.
- If no proxy is trusted, the verified `x-amzn-caller-arn` is matched against `PEP_ALLOWED_AGENT_ROLES` directly, as before, and the proxy role is what CloudTrail records. Anything else fails closed (401 or 403).
- Plane B does **not** verify either header cryptographically. They are only as trustworthy as the network path.

### Required controls

- The PEP security group admits 8081 only from the proxy Lambda's security group.
- Only the agent runtime role can invoke the proxy Lambda, and the proxy sets `x-pep-agent-role-arn` from the verified invoker, never from the request body.
- Restrict who can attach the proxy security group to other compute (IAM and EC2 permissions, CloudTrail alerts).
- `PEP_TRUSTED_PROXY_ROLES` lists the exact proxy role ARN and `PEP_ALLOWED_AGENT_ROLES` the agent role ARNs (full IAM role ARNs, not assumed-role ARNs).
- Plane A is exposed only to the VPN or Streamlit CIDR, never to the public internet.

### Configuration

| Setting | Value |
|---|---|
| `PEP_CALLER_ARN_HEADER` | `x-amzn-caller-arn` (default) |
| `PEP_ALLOWED_AGENT_ROLES` | The agent role ARNs. Empty allows any role in the carrier role's account. |
| `PEP_TRUSTED_PROXY_ROLES` | The proxy Lambda's role ARN. Plane B then reads the agent role from `x-pep-agent-role-arn` (sent by the proxy) and uses it as the STS `SourceIdentity`; the proxy name stays in the session name. See [pass-agent-identity-to-cloudtrail.md](./pass-agent-identity-to-cloudtrail.md). |
| `PEP_AGENT_ARN_HEADER` | `x-pep-agent-role-arn` (default) |
| `PEP_PLANE_B_URL` (client side) | `http://plane-b.<domain>:8081` |
| `REDIS_URL`, `PEP_ENCRYPTION_KEY` | Optional. Without Redis, sessions are in memory and the task count must stay at 1. |

### Known limitations (accepted for DEV/SBX)

- Anyone who can reach port 8081 with the right network identity can set the header and impersonate the proxy (gap 1).
- Traffic is plain HTTP inside the VPC (gap 2).
- Do not store production data or use production roles in this topology.

## Topology B: PROD with Private API Gateway and IAM auth

```
user --JWT--> PEP Plane A :8080 --> session_ref
user --prompt + session_ref--> Agent (AgentCore Runtime)
Agent --> Proxy Lambda --SigV4 (execute-api)--> Private API Gateway (VPC endpoint, IAM auth)
  --x-amzn-caller-arn = context.identity.userArn--> VPC link --> NLB --> PEP Plane B :8081
  --> Lake Formation / Athena --> user
```

### How the caller is identified

- The proxy Lambda signs each request with SigV4 using its execution role (service name `execute-api`). No secret is stored or rotated.
- API Gateway verifies the signature and the resource policy. Unsigned or unauthorised callers never reach the PEP.
- An integration request parameter maps `context.identity.userArn` to the header `x-amzn-caller-arn`. For an assumed role this is `arn:aws:sts::<account>:assumed-role/<role>/<session>`, which the PEP already parses.
- That verified role is the **proxy**. The proxy also sends the calling agent's role in `x-pep-agent-role-arn` (passed through the integration request), and Plane B reads it only because the proxy is listed in `PEP_TRUSTED_PROXY_ROLES`. See [proxy-lambda-integration-guide.md](./proxy-lambda-integration-guide.md).
- Plane B uses the same code path as in DEV/SBX. Only the source of the verified caller changes.

### Infrastructure to build

1. **Private REST API** reached through an `execute-api` interface VPC endpoint.
2. **Resource policy** that allows `execute-api:Invoke` only from that VPC endpoint and only for the proxy Lambda's role.
3. **Method auth** set to `AWS_IAM` on every Plane B method (`GET /mcp/tools`, `POST /mcp/tools/{tool}/call`, and `POST /mcp` if used).
4. **Integration request mapping**: `integration.request.header.x-amzn-caller-arn` = `context.identity.userArn`, and pass the proxy's `x-pep-agent-role-arn` through from the method request.
5. **VPC link and NLB** in front of the PEP task on port 8081. REST API VPC links target a Network Load Balancer.
6. **PEP security group** admits 8081 only from the NLB path. Remove the proxy Lambda's security group from the inbound rules.
7. **Path alignment**: the stage prefix must line up with the PEP's `/mcp/...` routes.

### Configuration

| Setting | Value |
|---|---|
| `PEP_CALLER_ARN_HEADER` | `x-amzn-caller-arn` |
| `PEP_TRUSTED_PROXY_ROLES` | The proxy Lambda's role ARN (full IAM role ARN) |
| `PEP_ALLOWED_AGENT_ROLES` | The agent role ARNs. Empty allows any role in the carrier role's account. |
| `PEP_AGENT_ARN_HEADER` | `x-pep-agent-role-arn` (default) |
| `PEP_PLANE_B_URL` (client side) | The private API invoke URL, including the stage |
| `PEP_SIGV4_SERVICE` (bridge agent) | `execute-api` |
| `REDIS_URL`, `PEP_ENCRYPTION_KEY` | Recommended for more than one PEP task |

### Changes versus DEV/SBX

- **PEP code and image:** none.
- **Bridge agent code:** none. It already SigV4-signs requests and reads the service name from `PEP_SIGV4_SERVICE`. API Gateway supports normal payload signing, so no `UNSIGNED-PAYLOAD` change is needed.
- **Proxy Lambda:** it must SigV4-sign its Plane B calls with the `execute-api` service name. The Lambda's code is not in this repository, so confirm how it signs.
- **Infrastructure and environment settings:** everything listed above.

### Pre-production checks

1. **Header overwrite test.** Send a request through the API with your own `x-amzn-caller-arn` and confirm the PEP receives the mapped value, not yours. The AWS docs I reviewed do not state the overwrite behaviour explicitly, and the security property depends on it. If the client value is passed through, do not go to PROD with this setup.
2. **Direct access test.** Confirm that port 8081 is unreachable except through the NLB path.
3. **Negative tests.** Unsigned call, call signed by another role, and a call with an unlisted role must all be rejected (403 from API Gateway or the PEP).
4. **Long query test.** The default API Gateway integration timeout is 29 seconds, while Athena queries can run up to `ATHENA_TIMEOUT_SECONDS` (90 by default). Raise the limit for the private REST API if the quota allows, or confirm the longest expected query fits.
5. **End-to-end test** with a real user session, a query, and a CloudTrail check that the query is attributed to the user's identity.

### What this closes

- **Gap 1** (header trust): the caller is verified by API Gateway, and the header is set by the gateway.
- **Gap 2** (plain HTTP): the client-to-API leg is HTTPS. The NLB-to-PEP leg stays inside the VPC, so add TLS on the NLB listener and the PEP if you need encryption on that leg as well.

### What it does not close

- **Gap 4**: the verified identity is the proxy role, not the user. A leaked `session_ref` is still usable by anything that can call the API as the proxy role.
- **Gaps 3, 5, 7**: these sit at the identity layer (Entra audiences, token handling, entitlement checks) and are independent of this choice.

## Choosing a topology

| Question | DEV/SBX | PROD |
|---|---|---|
| Cost | No extra service | A private REST API, a VPC endpoint (per AZ) and an NLB |
| Operational effort | Low | Medium (API, VPC link, mapping, resource policy) |
| Spoofing risk | Depends on network controls | Depends on API Gateway and the mapping |
| Secrets | None | None |
| Suitable for real data | No | Yes, after the pre-production checks |

## Promotion checklist (DEV/SBX to PROD)

1. Build the private API, VPC endpoint, VPC link and NLB.
2. Move the PEP security group inbound rule from the Lambda's security group to the NLB path.
3. Point the proxy Lambda at the API URL and sign with `execute-api`.
4. Run the pre-production checks above.
5. Remove any remaining path that reaches port 8081 directly.
6. Enable Redis sessions and more than one PEP task if availability matters.
