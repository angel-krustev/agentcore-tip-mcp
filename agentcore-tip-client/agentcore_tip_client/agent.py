# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Invoke a AgentCoreTIP agent server with a post-MFA user token."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict


@dataclass
class InvocationResult:
    """Result from the agent server."""
    ok: bool
    data: dict
    query_execution_id: str | None = None
    error_type: str | None = None
    error: str | None = None


class AgentCoreTIPClient:
    """Client for calling a AgentCore-TIP-MCP-Broker agent server."""

    def __init__(self, url: str = "http://127.0.0.1:8080/invocations"):
        self.url = url

    def invoke(
        self,
        token: str,
        payload: dict | None = None,
        user_id: str = "default-user",
        session_id: str | None = None,
        timeout: int = 120,
    ) -> InvocationResult:
        """Send a request to the agent server.

        Parameters
        ----------
        token : str
            Post-MFA OIDC id_token (JWT).
        payload : dict, optional
            Request body forwarded to the registered runner.
        user_id : str
            End-user identifier propagated in the identity context.
        session_id : str, optional
            Session ID (auto-generated if omitted).
        timeout : int
            Request timeout in seconds.
        """
        import uuid
        if session_id is None:
            session_id = f"vt-{uuid.uuid4()}"

        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload or {}).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
                "x-amzn-bedrock-agentcore-runtime-session-id": session_id,
                "X-Amzn-Bedrock-AgentCore-Runtime-User-Id": user_id,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return InvocationResult(
                    ok=data.get("ok", True),
                    data=data,
                    query_execution_id=data.get("query_execution_id"),
                    error_type=data.get("error_type"),
                    error=data.get("error"),
                )
        except urllib.error.HTTPError as exc:
            error_data = exc.read().decode("utf-8", errors="replace")
            return InvocationResult(
                ok=False,
                data={"http_status": exc.code, "body": error_data},
                error=f"HTTP {exc.code}",
            )
        except urllib.error.URLError as exc:
            return InvocationResult(
                ok=False,
                data={},
                error=f"Cannot reach agent at {self.url}: {exc.reason}",
            )
        except Exception as exc:
            return InvocationResult(
                ok=False,
                data={},
                error=str(exc),
            )

    def wait_for_query(self, query_id: str, timeout: int = 60) -> dict:
        """
        Wait for an Athena query to complete.

        Note: This is a convenience method for the default Athena runner.
        For other runners, inspect the InvocationResult directly.
        """
        # The agent server tracks query status internally;
        # this is a placeholder for future polling support.
        time.sleep(timeout)
        return {"status": "unknown"}
