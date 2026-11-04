# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Secure Broker / Policy Enforcement Point (PEP) entry point.

The two interfaces run as two separate FastAPI apps on two separate ports, so the
network layer can keep human users away from the agent-facing plane:

* Plane A -- ``/sessions/init`` on ``PEP_PLANE_A_PORT`` (default 8080): REST identity
  ingestion, reachable by the VPN load balancer only.
* Plane B -- ``/mcp`` on ``PEP_PLANE_B_PORT`` (default 8081): deterministic MCP tool
  execution, reachable by the agent network only.

Each app mounts only its own router: Plane B's routes do not exist on Plane A's port
and vice versa. The LLM host (``agentcore_tip.server``) is a separate process and
never mounts these routers.

Usage:
    python -m agentcore_tip.core.pep_server
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from typing import Any, Optional

import uvicorn
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .config import pep_config
from .http_limits import BodySizeLimitMiddleware
from .middleware import limiter, uvicorn_kwargs
from .plane_a_ingest import router as ingest_router, validation_error_handler
from .plane_b_mcp import router as mcp_router, validate_agent_allow_list
from .session_store import SessionStoreConfigError, session_store

logger = logging.getLogger(__name__)


def _new_app(title: str) -> FastAPI:
    app = FastAPI(title=title)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    # Never echo submitted values (IDP JWTs) in 422 responses, on either plane.
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    # Counts streamed bytes; does not trust Content-Length. Limit read per request from config.
    app.add_middleware(BodySizeLimitMiddleware, get_max_bytes=lambda: pep_config.max_request_body_bytes)
    return app


def create_plane_a_app() -> FastAPI:
    app = _new_app("AgentCoreTIP PEP - Plane A (ingestion)")
    app.include_router(ingest_router)

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"status": "healthy", "service": "pep-plane-a"}

    return app


def create_plane_b_app() -> FastAPI:
    app = _new_app("AgentCoreTIP PEP - Plane B (MCP execution)")
    app.include_router(mcp_router)

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"status": "healthy", "service": "pep-plane-b"}

    @app.get("/mcp/health")
    def health() -> dict[str, Any]:
        return {
            "status": "healthy",
            "region": pep_config.aws_region,
            "database": pep_config.athena_database,
        }

    return app


plane_a_app = create_plane_a_app()
plane_b_app = create_plane_b_app()

__all__ = ["plane_a_app", "plane_b_app", "build_servers", "serve", "main"]


def build_servers(plane_a_port: Optional[int] = None, plane_b_port: Optional[int] = None) -> list[uvicorn.Server]:
    """One Uvicorn server per plane, sharing host/TLS settings from the environment."""
    ports = (
        ("plane A", plane_a_app, pep_config.plane_a_port if plane_a_port is None else plane_a_port),
        ("plane B", plane_b_app, pep_config.plane_b_port if plane_b_port is None else plane_b_port),
    )
    if ports[0][2] == ports[1][2] and ports[0][2] != 0:
        raise ValueError("Plane A and Plane B must listen on different ports.")
    servers = []
    for name, app, port in ports:
        kwargs = uvicorn_kwargs()
        kwargs["port"] = port
        logger.info("%s listening on %s:%s", name, kwargs["host"], port)
        servers.append(uvicorn.Server(uvicorn.Config(app, **kwargs)))
    return servers


async def _run(server: uvicorn.Server, others: list[uvicorn.Server]) -> None:
    try:
        await server.serve()
    finally:
        # If one plane stops (crash or signal), stop the other so the task is never half-up.
        for other in others:
            other.should_exit = True


async def serve(servers: list[uvicorn.Server]) -> None:
    await session_store.init()
    try:
        await asyncio.gather(*(_run(s, [o for o in servers if o is not s]) for s in servers))
    finally:
        await session_store.close()


def main() -> None:
    """Entry point for ``python -m agentcore_tip.core.pep_server``."""
    parser = argparse.ArgumentParser(description="AgentCoreTIP Secure Broker / PEP")
    parser.add_argument("--plane-a-port", type=int, default=None, help=f"Plane A port (default: {pep_config.plane_a_port})")
    parser.add_argument("--plane-b-port", type=int, default=None, help=f"Plane B port (default: {pep_config.plane_b_port})")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        validate_agent_allow_list()
    except ValueError as exc:
        raise SystemExit(f"Invalid PEP role configuration: {exc}")
    try:
        asyncio.run(serve(build_servers(args.plane_a_port, args.plane_b_port)))
    except SessionStoreConfigError as exc:
        # Misconfiguration (e.g. Redis without a valid PEP_ENCRYPTION_KEY): fail closed with just the reason.
        raise SystemExit(f"Configuration error: {exc}")


if __name__ == "__main__":
    main()
