# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Interface 2 -- MCP execution plane (``/mcp``).

A deterministic Policy Enforcement Point: no LLM lives here. Each tool call
carries only an opaque ``session_ref``; the PEP resolves it to the cached
Identity Center context, validates SQL with sqlglot, JIT down-scopes STS
credentials to the referenced tables, runs the work off the event loop, and
discards the credentials immediately afterwards.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from functools import partial
from typing import Any, Awaitable, Callable, NamedTuple, Optional

import boto3
from botocore.config import Config as BotocoreConfig
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field, ValidationError

from .config import pep_config
from .middleware import limiter
from .session_store import session_store
from .sql_guard import (
    SQLGuardError,
    account_id_for_role,
    generate_downscoped_policy,
    generate_metadata_policy,
    validate_and_extract_tables,
    validate_identifier,
)
from .strategies.sso_oidc import SsoOidcExchangeStrategy

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/mcp", tags=["Plane B - Execution"])

_CALL_PATH = "mcp"
# Caller ARNs are matched in full: partition, service, 12-digit account, role/assumed-role
# kind and role name. ``assumed-role`` is only valid with the sts service and ``role``
# only with iam, so the two forms cannot be mixed up.
_CALLER_ARN_RE = re.compile(
    r"arn:(?P<partition>aws|aws-cn|aws-us-gov):(?P<service>iam|sts)::(?P<account>\d{12})"
    r":(?P<kind>assumed-role|role)/(?P<rest>[\w+=,.@/-]{1,512})"
)
_AGENT_NAME_RE = re.compile(r"[\w+=,.@-]{2,64}")
_DEFAULT_MAX_LIST_TABLES = 50

# Callers only ever see these. Engine/catalog error text (missing table, unknown column,
# Lake Formation denial, S3 paths) would let an agent enumerate data it may not read, so the
# detail goes to the server log and nowhere else.
QUERY_FAILED_MESSAGE = "Query execution failed due to invalid syntax or permissions"
CATALOG_FAILED_MESSAGE = "Request failed due to invalid input or permissions"


class AthenaQueryError(RuntimeError):
    """Athena finished a query in FAILED/CANCELLED state. ``reason`` is for logs only."""

    def __init__(self, state: str, reason: str, query_id: str) -> None:
        super().__init__(f"Athena query {state}")
        self.state = state
        self.reason = reason
        self.query_id = query_id

TOOL_DEFINITIONS = [
    {
        "name": "query_lake_formation",
        "description": "Execute a Lake Formation governed read-only SQL query against Athena using a validated session_ref.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_ref": {"type": "string", "description": "Opaque user session identifier obtained during login."},
                "sql": {"type": "string", "description": "Read-only SQL query to execute."},
                "database": {"type": "string", "description": f"Target database (default: {pep_config.athena_database})"},
                "max_rows": {"type": "integer", "description": "Max rows to return (default: 100)"},
            },
            "required": ["session_ref", "sql"],
        },
    },
    {
        "name": "list_tables",
        "description": "List available tables in the Glue Data Catalog for schema discovery.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_ref": {"type": "string", "description": "Opaque user session identifier."},
                "database": {"type": "string", "description": "Database name."},
            },
            "required": ["session_ref"],
        },
    },
    {
        "name": "describe_table",
        "description": "Retrieve column definitions and schema for a specific table in the Glue Data Catalog.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_ref": {"type": "string", "description": "Opaque user session identifier."},
                "table": {"type": "string", "description": "Table name."},
                "database": {"type": "string", "description": "Database name."},
            },
            "required": ["session_ref", "table"],
        },
    },
]


class QueryLakeArgs(BaseModel):
    # The Athena workgroup is fixed server-side (pep_config.athena_workgroup). Unknown
    # fields, including a legacy ``workgroup``, are ignored and never reach AWS.
    session_ref: str
    sql: str
    database: Optional[str] = None
    max_rows: int = Field(default=100, ge=1, le=1000)


class ListTablesArgs(BaseModel):
    session_ref: str
    database: Optional[str] = None


class DescribeTableArgs(BaseModel):
    session_ref: str
    table: str
    database: Optional[str] = None


@router.get("/tools")
def list_mcp_tools() -> dict:
    return {"tools": TOOL_DEFINITIONS}


# ---------------------------------------------------------------------------
# Caller identity
# ---------------------------------------------------------------------------

class CallerIdentity(NamedTuple):
    """A verified agent role. ``role_arn`` is canonical: arn:<partition>:iam::<acct>:role/<name>.

    ``proxy_role_name`` is set when a trusted proxy forwarded the agent identity on the agent's behalf.
    """

    role_arn: str
    role_name: str
    proxy_role_name: Optional[str] = None


class _ParsedRoleArn(NamedTuple):
    partition: str
    account: str
    name: str
    path: Optional[str]  # None when unknown (assumed-role ARNs carry no path)
    session: Optional[str]


def _parse_role_arn(arn: str) -> Optional[_ParsedRoleArn]:
    """Strictly parse an IAM role ARN or STS assumed-role ARN; None if malformed."""
    match = _CALLER_ARN_RE.fullmatch(arn or "")
    if match is None:
        return None
    kind, service = match.group("kind"), match.group("service")
    segments = match.group("rest").split("/")
    if any(not segment for segment in segments):
        return None
    if kind == "assumed-role":
        # arn:aws:sts::<acct>:assumed-role/<RoleName>/<session>
        if service != "sts" or len(segments) != 2:
            return None
        name, path, session = segments[0], None, segments[1]
        if not _AGENT_NAME_RE.fullmatch(session):
            return None
    else:
        # arn:aws:iam::<acct>:role/<optional/path/><RoleName>
        if service != "iam":
            return None
        name, path, session = segments[-1], "/".join(segments[:-1]), None
    if not _AGENT_NAME_RE.fullmatch(name):
        return None
    return _ParsedRoleArn(match.group("partition"), match.group("account"), name, path, session)


def validate_agent_allow_list() -> None:
    """Startup check: every PEP_ALLOWED_AGENT_ROLES / PEP_TRUSTED_PROXY_ROLES entry must be a full IAM role ARN."""
    for setting, entries in (
        ("PEP_ALLOWED_AGENT_ROLES", pep_config.allowed_agent_roles),
        ("PEP_TRUSTED_PROXY_ROLES", pep_config.trusted_proxy_roles),
    ):
        for entry in entries:
            parsed = _parse_role_arn(entry)
            if parsed is None or parsed.session is not None:
                raise ValueError(
                    f"{setting}: {entry!r} is not a full IAM role ARN (expected arn:aws:iam::<account-id>:role/<name>)."
                )


def _is_authorized_agent(caller: _ParsedRoleArn) -> bool:
    # Default boundary: the agent must live in the same account as the carrier role.
    expected_account = account_id_for_role(pep_config.carrier_role_arn)
    if expected_account == "*" or caller.account != expected_account:
        return False
    if not pep_config.allowed_agent_roles:
        return True
    return _in_role_list(caller, pep_config.allowed_agent_roles)


def _is_trusted_proxy(caller: _ParsedRoleArn) -> bool:
    return _in_role_list(caller, pep_config.trusted_proxy_roles)


def _in_role_list(caller: _ParsedRoleArn, entries: tuple[str, ...]) -> bool:
    for entry in entries:
        allowed = _parse_role_arn(entry)
        if allowed is None or allowed.session is not None:
            continue
        if (allowed.partition, allowed.account, allowed.name) != (caller.partition, caller.account, caller.name):
            continue
        # Assumed-role ARNs carry no path; it can only be compared for iam role ARNs.
        if caller.path is not None and allowed.path != caller.path:
            continue
        return True
    return False


def _canonical_role_arn(parsed: _ParsedRoleArn) -> str:
    return f"arn:{parsed.partition}:iam::{parsed.account}:role/{parsed.name}"


def _get_caller_agent_identity(request: Request) -> CallerIdentity:
    """Return the calling agent's verified role from the SigV4-verified caller ARN.

    The full ARN (partition, service, account, role name) is validated and matched
    against the allow-list; a bare role-name suffix is never enough. The header must
    be injected by the SigV4-verifying front end, so Plane B must only be reachable
    from that network. Fails closed.

    When the verified caller is a trusted proxy (PEP_TRUSTED_PROXY_ROLES), the agent is the
    role the proxy forwards in ``pep_config.agent_arn_header`` and that role goes through the
    same allow-list. The header is never read for any other caller.
    """
    parsed = _parse_role_arn(request.headers.get(pep_config.caller_arn_header, ""))
    if parsed is None:
        raise HTTPException(status_code=401, detail="Missing or invalid caller identity.")
    if not _is_trusted_proxy(parsed):
        if not _is_authorized_agent(parsed):
            raise HTTPException(status_code=403, detail="Caller is not an authorized agent role.")
        return CallerIdentity(role_arn=_canonical_role_arn(parsed), role_name=parsed.name)

    forwarded = request.headers.getlist(pep_config.agent_arn_header)
    agent = _parse_role_arn(forwarded[0]) if len(forwarded) == 1 else None
    if agent is None:
        raise HTTPException(status_code=401, detail="Missing or invalid agent identity.")
    if not _is_authorized_agent(agent):
        raise HTTPException(status_code=403, detail="Caller is not an authorized agent role.")
    return CallerIdentity(
        role_arn=_canonical_role_arn(agent),
        role_name=agent.name,
        proxy_role_name=parsed.name,
    )


# ---------------------------------------------------------------------------
# Synchronous AWS helpers -- only ever invoked via run_in_executor
# ---------------------------------------------------------------------------

def _build_strategy() -> SsoOidcExchangeStrategy:
    return SsoOidcExchangeStrategy(
        client_id=pep_config.sso_client_id,
        role_arn=pep_config.carrier_role_arn,
        region=pep_config.aws_region,
        call_path=_CALL_PATH,
    )


def _aws_client(service: str, creds: dict) -> Any:
    return boto3.client(
        service,
        region_name=pep_config.aws_region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        config=BotocoreConfig(user_agent_extra=f"AgentCoreTIP/{_CALL_PATH}"),
    )


def _execute_athena_sync(creds: dict, sql: str, database: str, workgroup: str, max_rows: int) -> list[dict]:
    """Start, poll and fetch an Athena query. Blocks; run in an executor thread."""
    athena = _aws_client("athena", creds)
    request: dict[str, Any] = {
        "QueryString": sql,
        "QueryExecutionContext": {"Database": database, "Catalog": pep_config.athena_catalog},
        "WorkGroup": workgroup,
    }
    if pep_config.athena_output_location:
        request["ResultConfiguration"] = {"OutputLocation": pep_config.athena_output_location}

    query_id = athena.start_query_execution(**request)["QueryExecutionId"]

    deadline = time.monotonic() + pep_config.athena_timeout_seconds
    while True:
        status = athena.get_query_execution(QueryExecutionId=query_id)["QueryExecution"]["Status"]
        state = status["State"]
        if state == "SUCCEEDED":
            break
        if state in ("FAILED", "CANCELLED"):
            raise AthenaQueryError(state, str(status.get("StateChangeReason", "Unknown"))[:500], query_id)
        if time.monotonic() >= deadline:
            try:
                athena.stop_query_execution(QueryExecutionId=query_id)
            except ClientError:
                pass
            raise TimeoutError(f"Athena query timed out after {pep_config.athena_timeout_seconds} seconds.")
        time.sleep(pep_config.athena_poll_seconds)

    # The first page's first row is the header row.
    page = athena.get_query_results(QueryExecutionId=query_id, MaxResults=min(max_rows + 1, 1000))
    raw_rows = page.get("ResultSet", {}).get("Rows", [])
    if len(raw_rows) < 2:
        return []
    headers = [col.get("VarCharValue", f"col_{i}") for i, col in enumerate(raw_rows[0].get("Data", []))]
    records: list[dict] = []
    for row in raw_rows[1:max_rows + 1]:
        data = row.get("Data", [])
        records.append({headers[i]: cell.get("VarCharValue") for i, cell in enumerate(data) if i < len(headers)})
    return records


def _glue_list_tables_sync(creds: dict, database: str, max_results: int) -> list[dict]:
    glue = _aws_client("glue", creds)
    response = glue.get_tables(DatabaseName=database, MaxResults=max_results)
    return [
        {"name": t["Name"], "table_type": t.get("TableType", "UNKNOWN")}
        for t in response.get("TableList", [])
    ]


def _glue_describe_table_sync(creds: dict, database: str, table: str) -> dict:
    glue = _aws_client("glue", creds)
    table_obj = glue.get_table(DatabaseName=database, Name=table)["Table"]
    descriptor = table_obj.get("StorageDescriptor", {})
    return {
        "columns": [{"name": c["Name"], "type": c.get("Type", "unknown")} for c in descriptor.get("Columns", [])],
        "partition_keys": [{"name": c["Name"], "type": c.get("Type", "unknown")} for c in table_obj.get("PartitionKeys", [])],
        "table_type": table_obj.get("TableType", "UNKNOWN"),
    }


async def _run_blocking(func: Callable[..., Any], *args: Any) -> Any:
    return await asyncio.get_running_loop().run_in_executor(None, partial(func, *args))


async def _vend_credentials(session: dict, agent_name: str, policy: str, proxy_name: Optional[str] = None) -> dict:
    strategy = _build_strategy()
    # The same UUID is appended to the STS RoleSessionName, so a CloudTrail event can be
    # matched to this log line (and to the caller's request) by searching for it.
    request_id = str(uuid.uuid4())
    # SourceIdentity is the agent; the proxy that forwarded it stays visible in the session name.
    credentials = await _run_blocking(
        partial(
            strategy.assume_downscoped_role,
            session["idc_context"],
            agent_name,
            policy,
            900,
            pep_config.aws_region,
            session_name=f"pep-{proxy_name}" if proxy_name else None,
            request_id=request_id,
        )
    )
    logger.info(
        "Assumed carrier role: agent=%s proxy=%s user=%s request_id=%s",
        agent_name, proxy_name, session.get("user_id"), request_id,
    )
    return credentials


def _truncate_rows(rows: list[dict]) -> tuple[list[dict], bool]:
    """Trim rows so the serialized payload stays under ``max_response_bytes``."""
    limit = pep_config.max_response_bytes
    total = 2
    for index, row in enumerate(rows):
        total += len(json.dumps(row, default=str)) + 1
        if total > limit:
            return rows[:index], True
    return rows, False


def _error(message: str, **extra: Any) -> dict:
    return {"ok": False, "error": message, **extra}


def _aws_error(prefix: str, err: ClientError) -> dict:
    code = err.response.get("Error", {}).get("Code", "Unknown")
    return _error(f"{prefix} ({code})")


def _log_aws_failure(tool: str, agent_name: str, session: dict, err: Exception) -> None:
    """Record the real AWS failure server-side; %r keeps newlines in AWS text from forging log lines."""
    if isinstance(err, ClientError):
        error = err.response.get("Error", {})
        detail = f"{error.get('Code', 'Unknown')}: {str(error.get('Message', ''))[:500]}"
    elif isinstance(err, AthenaQueryError):
        detail = f"{err.state} query_id={err.query_id}: {err.reason}"
    else:
        detail = type(err).__name__
    logger.warning("%s failed: agent=%s user=%s detail=%r", tool, agent_name, session.get("user_id"), detail)


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

async def _tool_query_lake_formation(
    args: QueryLakeArgs, session: dict, agent_name: str, proxy_name: Optional[str] = None,
) -> dict:
    database = args.database or pep_config.athena_database
    workgroup = pep_config.athena_workgroup
    try:
        validate_identifier(workgroup, "workgroup")
        cleaned_sql, target_tables = validate_and_extract_tables(
            args.sql, default_db=database, catalog=pep_config.athena_catalog,
        )
        policy = generate_downscoped_policy(
            target_tables,
            catalog=pep_config.athena_catalog,
            region=pep_config.aws_region,
            account_id=account_id_for_role(pep_config.carrier_role_arn),
            workgroup=workgroup,
            output_location=pep_config.athena_output_location,
        )
    except SQLGuardError as err:
        return _error(str(err))

    try:
        creds = await _vend_credentials(session, agent_name, policy, proxy_name)
    except (ClientError, BotoCoreError, ValueError) as err:
        if isinstance(err, ClientError):
            return _aws_error("STS Authorization Denied", err)
        logger.exception("Downscoped role assumption failed")
        return _error("STS Authorization Denied")

    try:
        rows = await _run_blocking(_execute_athena_sync, creds, cleaned_sql, database, workgroup, args.max_rows)
    except (ClientError, AthenaQueryError) as err:
        _log_aws_failure("query_lake_formation", agent_name, session, err)
        return _error(QUERY_FAILED_MESSAGE)
    except BotoCoreError:
        logger.exception("Athena request failed")
        return _error("Athena request failed")
    except TimeoutError as exc:
        return _error(str(exc))
    finally:
        creds.clear()

    rows, truncated = _truncate_rows(rows)
    logger.info(
        "query_lake_formation agent=%s user=%s tables=%s rows=%d",
        agent_name, session.get("user_id"), target_tables, len(rows),
    )
    result: dict[str, Any] = {"ok": True, "rows_returned": len(rows), "rows": rows, "target_tables": target_tables}
    if truncated:
        result["truncated"] = True
    return result


async def _tool_list_tables(
    args: ListTablesArgs, session: dict, agent_name: str, proxy_name: Optional[str] = None,
) -> dict:
    database = args.database or pep_config.athena_database
    try:
        policy = generate_metadata_policy(
            database, None, pep_config.aws_region, account_id_for_role(pep_config.carrier_role_arn),
        )
    except SQLGuardError as err:
        return _error(str(err))
    try:
        creds = await _vend_credentials(session, agent_name, policy, proxy_name)
    except ClientError as err:
        return _aws_error("STS Authorization Denied", err)
    except (BotoCoreError, ValueError):
        logger.exception("Downscoped role assumption failed")
        return _error("STS Authorization Denied")
    try:
        tables = await _run_blocking(_glue_list_tables_sync, creds, database, _DEFAULT_MAX_LIST_TABLES)
    except ClientError as err:
        _log_aws_failure("list_tables", agent_name, session, err)
        return _error(CATALOG_FAILED_MESSAGE)
    except BotoCoreError:
        logger.exception("Glue request failed")
        return _error("Glue request failed")
    finally:
        creds.clear()
    return {"ok": True, "database": database, "tables": tables, "count": len(tables)}


async def _tool_describe_table(
    args: DescribeTableArgs, session: dict, agent_name: str, proxy_name: Optional[str] = None,
) -> dict:
    database = args.database or pep_config.athena_database
    try:
        validate_identifier(args.table, "table")
        policy = generate_metadata_policy(
            database, args.table.lower(), pep_config.aws_region, account_id_for_role(pep_config.carrier_role_arn),
        )
    except SQLGuardError as err:
        return _error(str(err))
    try:
        creds = await _vend_credentials(session, agent_name, policy, proxy_name)
    except ClientError as err:
        return _aws_error("STS Authorization Denied", err)
    except (BotoCoreError, ValueError):
        logger.exception("Downscoped role assumption failed")
        return _error("STS Authorization Denied")
    try:
        description = await _run_blocking(_glue_describe_table_sync, creds, database, args.table.lower())
    except ClientError as err:
        _log_aws_failure("describe_table", agent_name, session, err)
        return _error(CATALOG_FAILED_MESSAGE)
    except BotoCoreError:
        logger.exception("Glue request failed")
        return _error("Glue request failed")
    finally:
        creds.clear()
    return {"ok": True, "database": database, "table": args.table, **description}


_TOOL_HANDLERS: dict[str, tuple[type, Callable[..., Awaitable[dict]]]] = {
    "query_lake_formation": (QueryLakeArgs, _tool_query_lake_formation),
    "list_tables": (ListTablesArgs, _tool_list_tables),
    "describe_table": (DescribeTableArgs, _tool_describe_table),
}


async def _dispatch_tool(tool_name: str, arguments: Any, caller: CallerIdentity) -> dict:
    handler_entry = _TOOL_HANDLERS.get(tool_name)
    if handler_entry is None:
        return _error(f"Unknown tool '{tool_name}'")
    args_model, handler = handler_entry
    try:
        args = args_model.model_validate(arguments if isinstance(arguments, dict) else {})
    except ValidationError as err:
        return _error("Invalid arguments: " + "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in err.errors()
        ))

    session = await session_store.get_session(args.session_ref)
    if not session:
        return _error("Invalid or expired session_ref")

    # Trust on first use: the first agent role to present this session_ref owns it.
    # The bound identity lives in the session store (Redis SET NX), so it is enforced
    # across replicas and expires with the session.
    expires_at = float(session.get("expires_at") or time.time() + pep_config.session_ttl_seconds)
    if not await session_store.bind_agent(args.session_ref, caller.role_arn, expires_at):
        logger.warning("session_ref presented by a different agent than the one it is bound to: caller=%s", caller.role_arn)
        return _error("Session is bound to a different agent identity.")
    return await handler(args, session, caller.role_name, caller.proxy_role_name)


# Request size is enforced for the whole app by BodySizeLimitMiddleware (http_limits.py), which
# counts the streamed bytes instead of trusting the Content-Length header.


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/tools/{tool_name}/call")
@limiter.limit(os.environ.get("RATE_LIMIT_TOOL_CALLS", "20/minute"))
async def call_tool(request: Request, tool_name: str) -> dict:
    caller = _get_caller_agent_identity(request)
    try:
        body = await request.json()
    except Exception:
        return _error("Request body must be valid JSON.")
    # Accept {"arguments": {...}} or flat arguments.
    arguments = body.get("arguments", body) if isinstance(body, dict) else {}
    return await _dispatch_tool(tool_name, arguments, caller)


def _rpc_result(request_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _rpc_error(request_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


@router.post("")
@limiter.limit(os.environ.get("RATE_LIMIT_TOOL_CALLS", "20/minute"))
async def mcp_jsonrpc(request: Request) -> Response:
    """Minimal MCP JSON-RPC 2.0 endpoint (initialize, tools/list, tools/call)."""
    caller = _get_caller_agent_identity(request)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(_rpc_error(None, -32700, "Parse error"))
    if not isinstance(body, dict) or "method" not in body:
        return JSONResponse(_rpc_error(None, -32600, "Invalid Request"))

    request_id = body.get("id")
    method = body["method"]
    params = body.get("params") or {}
    if not isinstance(params, dict):
        return JSONResponse(_rpc_error(request_id, -32602, "Invalid params"))
    if request_id is None:
        return Response(status_code=202)  # notification
    if method == "initialize":
        return JSONResponse(_rpc_result(request_id, {
            "protocolVersion": "2025-03-26",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "agentcore_tip-pep", "version": "0.1.0"},
        }))
    if method == "ping":
        return JSONResponse(_rpc_result(request_id, {}))
    if method == "tools/list":
        return JSONResponse(_rpc_result(request_id, {"tools": TOOL_DEFINITIONS}))
    if method == "tools/call":
        result = await _dispatch_tool(str(params.get("name", "")), params.get("arguments"), caller)
        return JSONResponse(_rpc_result(request_id, {
            "content": [{"type": "text", "text": json.dumps(result, default=str)}],
            "isError": not result.get("ok", False),
        }))
    return JSONResponse(_rpc_error(request_id, -32601, f"Method not found: {method}"))
