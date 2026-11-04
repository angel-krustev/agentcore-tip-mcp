"""Example AgentCore-compatible Athena/Lake Formation runner.

Run locally:
    python -m uvicorn agents.athena_lf_agent:app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import os
import time
from typing import Any

from agentcore_tip.server import app, register_runner

DEFAULT_DATABASE = os.environ.get("ATHENA_DATABASE", "lfdb")
DEFAULT_TABLE = os.environ.get("ATHENA_TABLE", "clients")
DEFAULT_WORKGROUP = os.environ.get("ATHENA_WORKGROUP", "idc-wg")
DEFAULT_CATALOG = os.environ.get("ATHENA_CATALOG", "AwsDataCatalog")
DEFAULT_LIMIT = int(os.environ.get("ATHENA_LIMIT", "10"))
DEFAULT_POLL_SECONDS = float(os.environ.get("ATHENA_POLL_SECONDS", "1"))
DEFAULT_TIMEOUT_SECONDS = float(os.environ.get("ATHENA_TIMEOUT_SECONDS", "60"))


@app.get("/athena-lf/health")
def athena_lf_health() -> dict[str, str]:
    return {
        "runner": "agents.athena_lf_agent",
        "workgroup": DEFAULT_WORKGROUP,
        "database": DEFAULT_DATABASE,
        "table": DEFAULT_TABLE,
    }


def _build_query(payload: dict[str, Any]) -> str:
    if payload.get("query"):
        return str(payload["query"])
    database = str(payload.get("database") or DEFAULT_DATABASE)
    table = str(payload.get("table") or DEFAULT_TABLE)
    limit = int(payload.get("limit") or DEFAULT_LIMIT)
    return f'SELECT * FROM "{database}"."{table}" LIMIT {limit}'


def _start_query(athena, query: str, payload: dict[str, Any]) -> str:
    database = str(payload.get("database") or DEFAULT_DATABASE)
    request: dict[str, Any] = {
        "QueryString": query,
        "QueryExecutionContext": {
            "Catalog": str(payload.get("catalog") or DEFAULT_CATALOG),
            "Database": database,
        },
        "WorkGroup": str(payload.get("workgroup") or DEFAULT_WORKGROUP),
    }
    output_location = payload.get("output_location") or os.environ.get("ATHENA_OUTPUT_LOCATION")
    if output_location:
        request["ResultConfiguration"] = {"OutputLocation": str(output_location)}
    response = athena.start_query_execution(**request)
    return str(response["QueryExecutionId"])


def _wait_for_query(athena, query_execution_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + DEFAULT_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        response = athena.get_query_execution(QueryExecutionId=query_execution_id)
        status = response["QueryExecution"]["Status"]
        state = status["State"]
        if state in {"SUCCEEDED", "FAILED", "CANCELLED"}:
            return response
        time.sleep(DEFAULT_POLL_SECONDS)
    raise TimeoutError(f"Athena query {query_execution_id} did not finish within {DEFAULT_TIMEOUT_SECONDS} seconds.")


def _rows_to_dicts(result_response: dict[str, Any]) -> list[dict[str, str | None]]:
    rows = result_response.get("ResultSet", {}).get("Rows", [])
    if not rows:
        return []
    headers = [col.get("VarCharValue", "") for col in rows[0].get("Data", [])]
    values = []
    for row in rows[1:]:
        data = row.get("Data", [])
        values.append(
            {
                headers[index]: cell.get("VarCharValue")
                for index, cell in enumerate(data)
                if index < len(headers)
            }
        )
    return values


@register_runner
def run_clients_query(context, payload: dict[str, Any]) -> dict[str, Any]:
    """Run an Athena query using credentials exchanged for the inbound user token."""
    query = _build_query(payload)
    athena = context.lakeformation_session().client("athena")
    query_execution_id = _start_query(athena, query, payload)
    execution = _wait_for_query(athena, query_execution_id)
    status = execution["QueryExecution"]["Status"]
    state = status["State"]
    if state != "SUCCEEDED":
        return {
            "ok": False,
            "query_execution_id": query_execution_id,
            "state": state,
            "reason": status.get("StateChangeReason", "Athena query did not succeed."),
        }
    result_response = athena.get_query_results(QueryExecutionId=query_execution_id, MaxResults=int(payload.get("max_results", 25)))
    return {
        "ok": True,
        "query_execution_id": query_execution_id,
        "workgroup": str(payload.get("workgroup") or DEFAULT_WORKGROUP),
        "database": str(payload.get("database") or DEFAULT_DATABASE),
        "table": str(payload.get("table") or DEFAULT_TABLE),
        "query": query,
        "rows": _rows_to_dicts(result_response),
    }
