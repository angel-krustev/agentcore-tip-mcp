"""MFA test client for the Secure Broker / PEP.

Walks the full dual-interface flow against a running PEP:

  1. Browser login with PKCE -- your IdP (Entra ID / Okta / Cognito) enforces MFA.
  2. POST /sessions/init  -> the PEP exchanges the JWT and returns an opaque session_ref.
  3. Plane B tool calls   -> list_tables, describe_table, query_lake_formation,
                            sending only session_ref (+ SQL), never the token.

Plane B identifies the calling *agent* from the SigV4-verified caller ARN. This
client can play the agent two ways:

  * default: send an ``x-amzn-caller-arn`` header (only valid against a PEP that is
    NOT behind the SigV4-verifying front end, i.e. a local/dev PEP).
  * --sigv4: sign requests with your local AWS credentials (for a deployed PEP).

Usage (PowerShell):

    # terminal 1 -- local PEP (needs ambient AWS creds allowed to assume the TIP role)
    $env:SSO_CLIENT_ID = "<token-exchange-application-arn>"
    $env:TIP_ROLE_ARN  = "<final-lake-formation-tip-role-arn>"
    $env:OIDC_ROLE_ARN = "<intermediary-oidc-role-arn>"
    $env:ATHENA_OUTPUT_LOCATION = "s3://<results-bucket>/pep/"
    python -m agentcore_tip.core.pep_server   # Plane A on 8080, Plane B on 8081

    # terminal 2 -- this client (Entra ID example)
    $env:ENTRA_TENANT_ID = "<tenant-id>"
    $env:OIDC_CLIENT_ID  = "<entra-native-public-client-id>"
    python -m examples.mfa_pep_client --require-mfa --negative-checks
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import uuid
from typing import Any, Optional

import httpx
import jwt

from examples.mfa_athena_client import _read_token


class PepClient:
    def __init__(self, args: argparse.Namespace) -> None:
        # Plane A (user ingestion) and Plane B (agent MCP) are separate listeners.
        self.plane_a_url = args.plane_a_url.rstrip("/")
        self.base_url = args.plane_b_url.rstrip("/")
        self.args = args
        self.http = httpx.Client(timeout=args.timeout)
        self._caller_override: Optional[str] = None

    @contextlib.contextmanager
    def as_caller(self, arn: str):
        """Temporarily present a different caller ARN (header mode only)."""
        self._caller_override = arn
        try:
            yield
        finally:
            self._caller_override = None

    def _caller_arn(self) -> str:
        if self._caller_override:
            return self._caller_override
        if self.args.caller_arn:
            return self.args.caller_arn
        return f"arn:aws:sts::{self.args.account_id}:assumed-role/{self.args.agent_role}/mfa-test-{uuid.uuid4().hex[:8]}"

    def _headers(self, method: str, url: str, body: bytes, with_caller: bool) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if not with_caller:
            return headers
        if not self.args.sigv4:
            headers["x-amzn-caller-arn"] = self._caller_arn()
            return headers

        import boto3
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest

        session = boto3.Session()
        credentials = session.get_credentials()
        if credentials is None:
            raise RuntimeError("--sigv4 needs local AWS credentials.")
        region = self.args.region or session.region_name or "us-east-1"
        request = AWSRequest(method=method, url=url, data=body, headers=headers)
        SigV4Auth(credentials.get_frozen_credentials(), self.args.sigv4_service, region).add_auth(request)
        return dict(request.headers.items())

    def request(self, method: str, path: str, payload: Optional[dict[str, Any]] = None, with_caller: bool = True) -> httpx.Response:
        url = f"{self.base_url}{path}"
        body = json.dumps(payload).encode() if payload is not None else b""
        return self.http.request(
            method, url, content=body or None, headers=self._headers(method, url, body, with_caller),
        )

    def tool(self, name: str, session_ref: str, **arguments: Any) -> httpx.Response:
        body = {k: v for k, v in arguments.items() if v is not None}
        body["session_ref"] = session_ref
        return self.request("POST", f"/mcp/tools/{name}/call", body)


def _show(title: str, value: Any) -> None:
    print(f"\n== {title}")
    print(value if isinstance(value, str) else json.dumps(value, indent=2, default=str))


def _report_mfa(token: str, require_mfa: bool) -> None:
    """Print non-sensitive identity claims; the raw token is never printed.

    ``amr`` is optional: when the IdP includes it, it is reported and (with
    --require-mfa) must contain 'mfa'. When absent or empty it is treated as
    empty and the flow continues, since MFA is then enforced only by the IdP.
    """
    claims = jwt.decode(token, options={"verify_signature": False})
    amr = claims.get("amr") or []
    _show("Login claims", {
        "user": claims.get("preferred_username") or claims.get("upn") or claims.get("email") or claims.get("sub"),
        "amr": amr,
        "acr": claims.get("acr"),
        "expires": claims.get("exp"),
    })
    if not amr:
        print("NOTE: id_token has no 'amr' claim; MFA is enforced by the IdP policy only and cannot be verified here.")
    elif require_mfa and "mfa" not in amr:
        raise SystemExit("FAIL: id_token 'amr' does not contain 'mfa'; refusing to continue (--require-mfa).")


def _negative_checks(client: PepClient, session_ref: str) -> list[str]:
    """Things the PEP must refuse. Returns a list of failures."""
    failures: list[str] = []

    def expect(label: str, ok: bool) -> None:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
        if not ok:
            failures.append(label)

    resp = client.request(
        "POST", "/mcp/tools/query_lake_formation/call",
        {"session_ref": session_ref, "sql": "SELECT 1 FROM x"}, with_caller=False,
    )
    expect("missing caller identity is rejected (401)", resp.status_code == 401)

    resp = client.tool("query_lake_formation", "sess_" + "0" * 32, sql='SELECT * FROM "lfdb"."clients"')
    expect("unknown session_ref is rejected", resp.status_code == 200 and resp.json().get("ok") is False)

    for label, sql in (
        ("DROP TABLE is rejected", 'DROP TABLE "lfdb"."clients"'),
        ("stacked statements are rejected", 'SELECT * FROM "lfdb"."clients"; DROP TABLE "lfdb"."clients"'),
        ("INSERT is rejected", 'INSERT INTO "lfdb"."clients" SELECT * FROM "lfdb"."clients"'),
    ):
        resp = client.tool("query_lake_formation", session_ref, sql=sql)
        expect(label, resp.status_code == 200 and resp.json().get("ok") is False)

    names = {t["name"] for t in client.request("GET", "/mcp/tools").json().get("tools", [])}
    expect("no LLM tools are exposed", not names & {"generate_sql", "explain_query", "query_data"})
    props = [p for t in client.request("GET", "/mcp/tools").json().get("tools", []) for p in t["inputSchema"]["properties"]]
    expect("workgroup is not a tool parameter", "workgroup" not in props)

    if client.args.sigv4:
        print("  [SKIP] identity-forgery checks need header mode (a SigV4 client cannot impersonate another role)")
        return failures

    # Phase 2 checks. The session was bound to this client's agent role by the tool calls above.
    sql = 'SELECT id FROM "lfdb"."clients" LIMIT 1'
    other_role = f"arn:aws:sts::{client.args.account_id}:assumed-role/{client.args.other_agent_role}/forged-1"
    with client.as_caller(other_role):
        resp = client.tool("query_lake_formation", session_ref, sql=sql)
    if resp.status_code == 403:
        # Stronger than TOFU, but TOFU itself was not exercised: the allow-list stopped the other role first.
        print(f"  [PASS] other agent role {client.args.other_agent_role} is rejected by the allow-list (403)")
        print(f"  [SKIP] TOFU not reached; add {client.args.other_agent_role} to PEP_ALLOWED_AGENT_ROLES to exercise it")
    else:
        body = resp.json() if resp.status_code == 200 else {}
        expect("session replayed by a different (allowed) agent role is rejected (TOFU)",
               body.get("ok") is False and "bound" in str(body.get("error", "")))

    with client.as_caller(f"arn:aws:sts::999999999999:assumed-role/{client.args.agent_role}/forged-2"):
        resp = client.tool("query_lake_formation", session_ref, sql=sql)
    expect("same role name in another account is rejected (403)", resp.status_code == 403)

    with client.as_caller(f"arn:aws:sts::{client.args.account_id}:assumed-role/Not{client.args.agent_role}/forged-3"):
        resp = client.tool("query_lake_formation", session_ref, sql=sql)
    expect("role-name suffix lookalike is not treated as the allowed agent",
           resp.status_code == 403 or resp.json().get("ok") is False)

    resp = client.tool("query_lake_formation", session_ref, sql=sql, workgroup="attacker-chosen-wg")
    expect("a caller-supplied workgroup is ignored (query still runs in the server's workgroup)",
           resp.status_code == 200 and resp.json().get("ok") is True)

    # Phase 3: SQL guard hardening, generic errors.
    for label, probe in (
        ("information_schema.tables is blocked", 'SELECT * FROM information_schema.tables'),
        ("quoted/mixed-case INFORMATION_SCHEMA is blocked", 'SELECT * FROM "INFORMATION_SCHEMA"."columns"'),
        ("catalog-qualified information_schema is blocked", 'SELECT * FROM awsdatacatalog.information_schema.tables'),
        ("information_schema hidden in a subquery is blocked",
         'SELECT id FROM "lfdb"."clients" WHERE id IN (SELECT table_name FROM information_schema.tables)'),
    ):
        resp = client.tool("query_lake_formation", session_ref, sql=probe)
        body = resp.json() if resp.status_code == 200 else {}
        expect(label, body.get("ok") is False and "system schemas" in str(body.get("error", "")))

    resp = client.tool("query_lake_formation", session_ref, sql=sql, database="lfdb\n")
    expect("a trailing newline in the database name is rejected",
           resp.status_code == 200 and resp.json().get("ok") is False)

    generic_query = "Query execution failed due to invalid syntax or permissions"
    missing_table = client.tool("query_lake_formation", session_ref, sql='SELECT * FROM "lfdb"."zz_no_such_table_qa7"').json()
    missing_column = client.tool("query_lake_formation", session_ref, sql='SELECT zz_no_such_col_qa7 FROM "lfdb"."clients"').json()
    expect("a missing table returns only the generic query error",
           missing_table == {"ok": False, "error": generic_query})
    expect("a missing column returns only the generic query error (no column or table names)",
           missing_column == {"ok": False, "error": generic_query})
    expect("missing table and missing column are indistinguishable", missing_table == missing_column)

    described = client.tool("describe_table", session_ref, table="zz_no_such_table_qa7").json()
    leaked = [w for w in ("zz_no_such", "EntityNotFound", "not found", "does not exist") if w in json.dumps(described)]
    expect("describing a missing table returns a generic error with no existence signal",
           described.get("ok") is False and not leaked)

    # Phase 4: validation errors never echo the submitted value; size is enforced on streamed bytes.
    canary = "eyJCANARY.client-side-secret.sig"
    for label, body in (("a missing token", {"refresh_token": canary}), ("an over-long token", {"token": canary * 800})):
        resp = client.http.post(f"{client.plane_a_url}/sessions/init", json=body)
        expect(f"422 for {label} does not echo the submitted value",
               resp.status_code == 422 and "CANARY" not in resp.text and "client-side-secret" not in resp.text)

    def chunked_body(total: int):
        # A generator body is sent with chunked transfer encoding, i.e. without a Content-Length header.
        sent = 0
        while sent < total:
            yield b"x" * 65536
            sent += 65536

    big = client.args.oversize_bytes
    for label, url in (("Plane A", f"{client.plane_a_url}/sessions/init"), ("Plane B", f"{client.base_url}/mcp/tools/list_tables/call")):
        try:
            status = client.http.post(url, content=chunked_body(big), headers={"content-type": "application/json"}).status_code
        except httpx.TransportError:
            status = None  # a reset instead of a 413 means the server closed with unread data
        expect(f"{label}: a chunked {big // 1024} KiB body without Content-Length is refused with 413", status == 413)
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="MFA end-to-end test client for the AgentCoreTIP PEP.")
    parser.add_argument("--plane-a-url", default=os.environ.get("PEP_PLANE_A_URL", "http://127.0.0.1:8080"), help="Plane A (ingestion, user-facing).")
    parser.add_argument("--plane-b-url", default=os.environ.get("PEP_PLANE_B_URL", "http://127.0.0.1:8081"), help="Plane B (MCP, agent-facing).")
    parser.add_argument("--timeout", type=float, default=float(os.environ.get("PEP_TIMEOUT_SECONDS", "120")))
    parser.add_argument("--token", help="Post-MFA JWT. If omitted, a browser MFA login is started. Env: USER_TOKEN")
    parser.add_argument("--no-browser-login", action="store_true", help="Prompt for an existing post-MFA JWT (hidden input).")
    parser.add_argument("--require-mfa", action="store_true", help="If the id_token has an 'amr' claim, require it to contain 'mfa'. An absent/empty amr is allowed.")
    parser.add_argument("--negative-checks", action="store_true", help="Also verify the PEP refuses unsafe requests.")

    agent = parser.add_argument_group("agent identity (Plane B caller)")
    agent.add_argument("--agent-role", default=os.environ.get("PEP_AGENT_ROLE", "FinancialAnalystAgentRole"))
    agent.add_argument("--other-agent-role", default=os.environ.get("PEP_OTHER_AGENT_ROLE", "IntruderAgentRole"),
                       help="A second role used to try to replay the session (TOFU check).")
    agent.add_argument("--account-id", default=os.environ.get("AWS_ACCOUNT_ID", "123456789012"))
    agent.add_argument("--caller-arn", default=os.environ.get("PEP_CALLER_ARN"), help="Full caller ARN header value (overrides --agent-role).")
    agent.add_argument("--sigv4", action="store_true", help="SigV4-sign with local AWS credentials instead of the caller-ARN header.")
    agent.add_argument("--sigv4-service", default=os.environ.get("PEP_SIGV4_SERVICE", "vpc-lattice-svcs"))
    agent.add_argument("--region", default=os.environ.get("AWS_REGION"))

    query = parser.add_argument_group("query")
    query.add_argument("--database", default="lfdb")
    query.add_argument("--table", default="clients")
    query.add_argument("--limit", type=int, default=10)
    query.add_argument("--oversize-bytes", type=int, default=3 * 1024 * 1024,
                       help="Size of the chunked body used to test the request-size limit (must exceed MAX_REQUEST_BODY_BYTES).")
    query.add_argument("--sql", help="Explicit read-only SQL (default: SELECT * FROM <database>.<table> LIMIT <limit>).")

    login = parser.add_argument_group("OIDC login (same options as examples.mfa_athena_client)")
    login.add_argument("--idp", default=os.environ.get("IDP"), help="entra-id | okta | cognito")
    login.add_argument("--oidc-discovery-url", default=os.environ.get("OIDC_DISCOVERY_URL"))
    login.add_argument("--oidc-authorization-endpoint")
    login.add_argument("--oidc-token-endpoint")
    login.add_argument("--oidc-client-id", default=os.environ.get("OIDC_CLIENT_ID"))
    login.add_argument("--oidc-redirect-uri", default=os.environ.get("OIDC_REDIRECT_URI"))
    login.add_argument("--config-file", default=os.environ.get("CONFIG_FILE"))
    login.add_argument("--oidc-scopes", default=os.environ.get("OIDC_SCOPES"))
    login.add_argument("--oidc-prompt", default=os.environ.get("OIDC_PROMPT", "login"))
    login.add_argument("--oidc-timeout-seconds", type=int, default=int(os.environ.get("OIDC_TIMEOUT_SECONDS", "300")))
    args = parser.parse_args()

    client = PepClient(args)

    try:
        for label, base in (("Plane A", client.plane_a_url), ("Plane B", client.base_url)):
            client.http.get(f"{base}/ping").raise_for_status()
    except httpx.HTTPError as exc:
        print(f"PEP is not reachable: {exc}", file=sys.stderr)
        return 2

    # Step 1: MFA login
    token = _read_token(args)
    _report_mfa(token, args.require_mfa)

    # Step 2: Plane A -- exchange once, receive only an opaque pointer
    init = client.http.post(f"{client.plane_a_url}/sessions/init", json={"token": token})
    del token  # nothing after this point needs the bearer token
    if init.status_code != 200:
        _show(f"POST /sessions/init failed ({init.status_code})", init.text)
        return 1
    session = init.json()
    session_ref = session["session_ref"]
    _show("Plane A: session established", {"session_ref": session_ref, "expires_in": session["expires_in"]})

    # Step 3: Plane B -- tool calls carry only session_ref
    tools = client.request("GET", "/mcp/tools")
    _show("Plane B: tools", [t["name"] for t in tools.json().get("tools", [])])

    failed = False
    calls = [
        ("list_tables", {"database": args.database}),
        ("describe_table", {"database": args.database, "table": args.table}),
        ("query_lake_formation", {
            "sql": args.sql or f'SELECT * FROM "{args.database}"."{args.table}" LIMIT {args.limit}',
            "database": args.database,
            "max_rows": args.limit,
        }),
    ]
    for name, arguments in calls:
        response = client.tool(name, session_ref, **arguments)
        if response.status_code != 200:
            _show(f"{name} -> HTTP {response.status_code}", response.text)
            failed = True
            continue
        body = response.json()
        _show(f"{name} -> ok={body.get('ok')}", body)
        failed = failed or not body.get("ok")

    if args.negative_checks:
        print("\n== Negative checks")
        failed = bool(_negative_checks(client, session_ref)) or failed

    print("\nRESULT:", "FAIL" if failed else "PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
