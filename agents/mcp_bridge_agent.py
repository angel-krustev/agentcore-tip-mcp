"""MCP Bridge Agent -- agent-side client for the Secure Broker / PEP.

This agent hosts the LLM (Bedrock Converse) and nothing else. It never sees
IDP bearer tokens, Identity Center assertions or user AWS credentials: it holds
only an opaque ``session_ref`` and calls the PEP's MCP execution plane over HTTP,
signing each request with the agent's own IAM role (SigV4).

Usage:
    python -m uvicorn agents.mcp_bridge_agent:app --host 0.0.0.0 --port 8080

Environment:
    PEP_PLANE_B_URL     Base URL of the PEP's Plane B (MCP) listener (default: http://127.0.0.1:8081).
                        The agent never talks to Plane A (8080); that is the user-facing ingestion port.
    PEP_SIGV4_SERVICE   SigV4 signing name (default: vpc-lattice-svcs)
    PEP_SIGN_REQUESTS   Set to "false" for local development against an unsigned PEP
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

import boto3
import httpx
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from agentcore_tip.core.agentcore_provider import get_runtime, AgentCoreAgentRuntime
from agentcore_tip.core.context import AgentCoreTIPContext
from agentcore_tip.server import app, register_runner

logger = logging.getLogger(__name__)

PEP_URL = os.environ.get("PEP_PLANE_B_URL", "http://127.0.0.1:8081").rstrip("/")
PEP_SIGV4_SERVICE = os.environ.get("PEP_SIGV4_SERVICE", "vpc-lattice-svcs")
PEP_SIGN_REQUESTS = os.environ.get("PEP_SIGN_REQUESTS", "true").lower() != "false"
PEP_TIMEOUT_SECONDS = float(os.environ.get("PEP_TIMEOUT_SECONDS", "120"))
BEDROCK_MODEL = os.environ.get("BEDROCK_MODEL", "anthropic.claude-3-haiku-20240307-v1:0")
_SESSION_REF_HEADER = "x-amzn-bedrock-agentcore-runtime-custom-sessionref"

runtime: AgentCoreAgentRuntime = get_runtime()


# ---------------------------------------------------------------------------
# PEP client
# ---------------------------------------------------------------------------

def _signed_headers(method: str, url: str, body: str) -> dict[str, str]:
    headers = {"content-type": "application/json"}
    if not PEP_SIGN_REQUESTS:
        return headers
    session = boto3.Session()
    credentials = session.get_credentials()
    if credentials is None:
        raise RuntimeError("No AWS credentials available to SigV4-sign PEP requests.")
    region = session.region_name or os.environ.get("AWS_REGION", "us-east-1")
    request = AWSRequest(method=method, url=url, data=body, headers=headers)
    SigV4Auth(credentials.get_frozen_credentials(), PEP_SIGV4_SERVICE, region).add_auth(request)
    return dict(request.headers.items())


def _pep_request(method: str, path: str, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    url = f"{PEP_URL}{path}"
    body = json.dumps(payload) if payload is not None else ""
    response = httpx.request(
        method,
        url,
        content=body or None,
        headers=_signed_headers(method, url, body),
        timeout=PEP_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()


def list_pep_tools() -> list[dict[str, Any]]:
    return _pep_request("GET", "/mcp/tools").get("tools", [])


def call_pep_tool(tool_name: str, arguments: dict[str, Any], session_ref: str) -> dict[str, Any]:
    """Invoke a PEP tool. Only ``session_ref`` and tool arguments cross the wire."""
    if not session_ref:
        return {"ok": False, "error": "session_ref is required"}
    body = {k: v for k, v in arguments.items() if v is not None}
    body["session_ref"] = session_ref
    try:
        return _pep_request("POST", f"/mcp/tools/{tool_name}/call", body)
    except httpx.HTTPStatusError as exc:
        return {"ok": False, "error": f"PEP returned HTTP {exc.response.status_code}"}
    except httpx.HTTPError as exc:
        logger.error("PEP call failed for %s: %s", tool_name, exc)
        return {"ok": False, "error": "PEP is unreachable"}


def _resolve_session_ref(context: AgentCoreTIPContext, payload: dict[str, Any]) -> str:
    session_ref = payload.get("session_ref")
    if session_ref:
        return str(session_ref)
    headers = context.actor_context.get("custom_headers") or {}
    for name, value in headers.items():
        if name.lower() == _SESSION_REF_HEADER:
            return str(value)
    return ""


def _llm_tool_specs(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Bedrock tool specs with ``session_ref`` hidden -- the agent injects it."""
    specs = []
    for tool in tools:
        schema = json.loads(json.dumps(tool["inputSchema"]))
        schema.get("properties", {}).pop("session_ref", None)
        schema["required"] = [r for r in schema.get("required", []) if r != "session_ref"]
        specs.append({
            "toolSpec": {
                "name": tool["name"],
                "description": tool["description"],
                "inputSchema": {"json": schema},
            }
        })
    return specs


# ---------------------------------------------------------------------------
# Health / discovery endpoints
# ---------------------------------------------------------------------------

@app.get("/bridge/health")
def bridge_health() -> dict[str, str]:
    return {
        "runner": "agents.mcp_bridge_agent",
        "pep_url": PEP_URL,
        "agentcore_runtime": "enabled",
    }


@app.get("/bridge/status")
def bridge_status() -> dict[str, Any]:
    """Detailed runtime status."""
    return runtime.get_status()


@app.get("/bridge/mcp/tools")
def bridge_mcp_tools() -> dict:
    """List the PEP's MCP tools."""
    tools = list_pep_tools()
    return {"tools": tools, "count": len(tools)}


@app.post("/bridge/mcp/tools/{tool_name}/call")
def bridge_mcp_call_tool(
    tool_name: str,
    session_ref: str,
    sql: str | None = None,
    table: str | None = None,
    database: str | None = None,
    max_rows: int | None = None,
) -> dict:
    """Forward a tool call to the PEP using only the opaque session_ref."""
    arguments = {"sql": sql, "table": table, "database": database, "max_rows": max_rows}
    result = call_pep_tool(tool_name, arguments, session_ref)
    result["tool"] = tool_name
    return result


# ---------------------------------------------------------------------------
# Registered runner -- Bedrock tool-use loop that delegates to the PEP
# ---------------------------------------------------------------------------

@register_runner
def run_bedrock_tool_agent(context: AgentCoreTIPContext, payload: dict[str, Any]) -> dict[str, Any]:
    """LLM reasons about the question and generates SQL; the PEP executes it.

    Flow: Claude decides which PEP tool to call -> agent forwards the call with
    ``session_ref`` -> PEP enforces identity and read-only access -> Claude
    summarizes the rows. The agent runs with its own role, never user credentials.
    """
    question = payload.get("question") or payload.get("input") or ""
    if not question:
        return {"ok": False, "error": "No question provided"}

    tool_name = payload.get("tool")
    session_ref = _resolve_session_ref(context, payload)
    if not session_ref:
        return {"ok": False, "error": "session_ref is required"}

    # Direct tool invocation, no LLM involved.
    if tool_name:
        result = call_pep_tool(tool_name, payload.get("tool_args", {}), session_ref)
        result["routed_via"] = "pep_tool"
        return result

    region = os.environ.get("AWS_REGION", "us-east-1")
    br = boto3.client("bedrock-runtime", region_name=region)
    system_prompt = (
        "You are a data analyst assistant. Use the provided tools to explore the schema "
        "and run read-only SQL (Athena/Presto dialect) to answer the user's question. "
        "Access is governed by the user's permissions; if a tool reports an access "
        "denial, tell the user politely. Default to LIMIT 20."
    )
    tool_config = {"tools": _llm_tool_specs(list_pep_tools()), "toolChoice": {"auto": {}}}
    inference_config = {"maxTokens": 4096, "temperature": 0.1}
    messages: list[dict[str, Any]] = [{"role": "user", "content": [{"text": question}]}]

    tools_used = 0
    final_answer = ""
    for _ in range(int(os.environ.get("MAX_TOOL_TURNS", "5"))):
        response = br.converse(
            modelId=BEDROCK_MODEL,
            messages=messages,
            system=[{"text": system_prompt}],
            toolConfig=tool_config,
            inferenceConfig=inference_config,
        )
        message = response.get("output", {}).get("message", {})
        blocks = message.get("content", [])
        messages.append({"role": "assistant", "content": blocks})

        tool_results = []
        for block in blocks:
            if "text" in block:
                final_answer = block["text"]
            if "toolUse" not in block:
                continue
            tool_use = block["toolUse"]
            result = call_pep_tool(tool_use["name"], tool_use.get("input", {}), session_ref)
            tools_used += 1
            tool_results.append({
                "toolResult": {
                    "toolUseId": tool_use.get("toolUseId", ""),
                    "content": [{"text": json.dumps(result, default=str)}],
                    "status": "success" if result.get("ok") else "error",
                }
            })
        if not tool_results:
            break
        messages.append({"role": "user", "content": tool_results})

    return {"ok": True, "question": question, "answer": final_answer, "tools_used": tools_used}
