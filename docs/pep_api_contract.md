# API contract

The broker exposes two separate interfaces:

- **Plane A:** `POST /sessions/init` accepts an identity-provider token and returns an opaque `session_ref`.
- **Plane B:** `POST /mcp/tools/{tool_name}/call` accepts that reference and a tool request. Tools include read-only queries and schema discovery.

Never send identity-provider tokens or AWS credentials to Plane B. Keep Plane B private behind an authenticated gateway that supplies the verified caller identity. See the [README](./README.md) for deployment guidance.

For current tool names and request schemas, use `GET /mcp/tools` on Plane B.
