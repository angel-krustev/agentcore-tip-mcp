# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""FastAPI service entrypoint for Bedrock AgentCore Runtime compatibility."""

from __future__ import annotations

import asyncio
import logging
import os
from functools import partial
from typing import Any, Callable

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .core.agent_validator import validate_on_startup
from .core.config import build_agent_actor_context
from .core.context import AgentCoreTIPContext
from .core.hooks import sanitize_for_log
from .core.http_limits import BodySizeLimitMiddleware
from .core.middleware import limiter, tls_context, uvicorn_kwargs

logger = logging.getLogger(__name__)
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False

# This is the LLM-hosting agent app. It must never mount the PEP planes
# (plane_a_ingest / plane_b_mcp); those run in a separate process via pep_server.
app = FastAPI(title="AgentCore-TIP-MCP-Broker Core")
app.state.limiter = limiter
# Bound request bodies by streamed bytes (not Content-Length), as in the PEP planes.
app.add_middleware(
    BodySizeLimitMiddleware,
    get_max_bytes=lambda: int(os.environ.get("MAX_REQUEST_BODY_BYTES", "1048576")),
)
_registered_runner: Callable[..., Any] | None = None

# ---------------------------------------------------------------------------
# Application startup — validate agent.json manifest
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def _startup_validate() -> None:
    """Validate agent.json on startup so misconfigurations fail fast."""
    try:
        validate_on_startup()
    except Exception as exc:
        logger.error("Startup validation failed: %s — server will continue with degraded validation", exc)


class InvocationRequest(BaseModel):
    input: Any | None = None
    session_id: str | None = None


@app.get("/ping")
def ping() -> dict[str, str]:
    """Health check endpoint — no rate limit."""
    return {"status": "Healthy"}


@app.post("/invocations")
@limiter.limit(os.environ.get("RATE_LIMIT_INVOCATIONS", "30/minute"))
async def invocations(
    request: Request,
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_amzn_bedrock_agentcore_runtime_session_id: str | None = Header(default=None, alias="x-amzn-bedrock-agentcore-runtime-session-id"),
    x_amzn_bedrock_agentcore_runtime_user_id: str | None = Header(default=None, alias="X-Amzn-Bedrock-AgentCore-Runtime-User-Id"),
):
    """Handle Bedrock AgentCore invocations with per-user rate limiting."""
    if _registered_runner is None:
        raise RuntimeError("No runner has been registered for AgentCore-TIP-MCP-Broker Core.")
    payload = await request.json() if request.headers.get("content-type", "").lower().startswith("application/json") else {}
    token = None
    if authorization:
        token = authorization.replace("Bearer ", "", 1) if authorization.lower().startswith("bearer ") else authorization
    custom_headers = {}
    for name, value in request.headers.items():
        if name.lower().startswith("x-amzn-bedrock-agentcore-runtime-custom-"):
            custom_headers[name] = value
    custom_user_token = custom_headers.get("X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserToken") or custom_headers.get("x-amzn-bedrock-agentcore-runtime-custom-usertoken")
    if custom_user_token and not token:
        token = custom_user_token.replace("Bearer ", "", 1) if custom_user_token.lower().startswith("bearer ") else custom_user_token
    user_id = x_amzn_bedrock_agentcore_runtime_user_id or ""
    session_id = x_amzn_bedrock_agentcore_runtime_session_id or "default-session"
    context = AgentCoreTIPContext(
        session_id=session_id,
        user_id=user_id,
        idp_token=token,
        actor_context=build_agent_actor_context(user_id, custom_headers),
    )
    # Runners are synchronous and may block on network calls; keep them off the event loop.
    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(None, partial(_registered_runner, context, payload))
    except Exception as exc:
        logger.exception("Unhandled exception while running the registered agent for session %s", session_id)
        error_payload = {
            "ok": False,
            "error_type": type(exc).__name__,
            "error": str(sanitize_for_log(str(exc))),
            "session_id": session_id,
        }
        return JSONResponse(status_code=500, content=error_payload)


def register_runner(fn: Callable[..., Any]) -> Callable[..., Any]:
    global _registered_runner
    _registered_runner = fn
    return fn
