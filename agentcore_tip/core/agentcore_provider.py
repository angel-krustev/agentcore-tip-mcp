# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Managed AgentCore Runtime provider for AgentCore-TIP-MCP-Broker.

Wires AgentCoreTIPContext (TIP credentials) into Bedrock AgentCore Runtime's
credential lifecycle. This allows agents to run as managed Bedrock AgentCore
instances while maintaining per-user credential caching and identity propagation.

Key capabilities:
  - Managed credential provider for AgentCore Runtime
  - Automatic TIP token refresh on credential expiry
  - Session-scoped credential isolation
  - Health check and status endpoints for AgentCore compatibility

Usage:
    from agentcore_tip.core.agentcore_provider import AgentCoreCredentialProvider

    provider = AgentCoreCredentialProvider(
        session_id="user-123",
        user_id="idc_user_id",
        idp_token="<IDP_TOKEN>",
    )
    # AgentCore will call provider.get_credentials() when it needs AWS creds
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import boto3

from .config import build_agent_actor_context
from .context import AgentCoreTIPContext

logger = logging.getLogger(__name__)


@dataclass
class AgentCoreCredentialSet:
    """Credentials compatible with AgentCore Runtime expectations."""
    access_key: str
    secret_key: str
    session_token: str
    expires_at: float  # epoch seconds
    user_id: str
    session_id: str

    def is_expired(self, buffer_seconds: int = 60) -> bool:
        return time.time() >= (self.expires_at - buffer_seconds)

    def to_botocore_credentials(self) -> dict[str, str]:
        """Format for botocore credential providers."""
        return {
            "access_key": self.access_key,
            "secret_key": self.secret_key,
            "token": self.session_token,
        }


class AgentCoreCredentialProvider:
    """Managed credential provider for Bedrock AgentCore Runtime.

    Integrates AgentCoreTIPContext's TIP credential exchange with AgentCore's
    credential lifecycle. AgentCore calls get_credentials() periodically; this
    provider returns cached creds if valid, or performs a fresh TIP exchange.

    The loading sentinel pattern from AgentCoreTIPContext prevents concurrent
    exchanges, so even under AgentCore's polling, we get at most 1 exchange
    per user per credential TTL.
    """

    def __init__(
        self,
        session_id: str,
        user_id: str,
        idp_token: Optional[str] = None,
        actor_context: Optional[dict[str, Any]] = None,
    ) -> None:
        self.session_id = session_id
        self.user_id = user_id
        self.idp_token = idp_token
        self._actor_context = actor_context or build_agent_actor_context(user_id, {})
        self._tip_context: Optional[AgentCoreTIPContext] = None
        self._last_creds: Optional[AgentCoreCredentialSet] = None
        self._last_fetch: float = 0

    def _ensure_tip_context(self) -> AgentCoreTIPContext:
        """Lazily create AgentCoreTIPContext."""
        if self._tip_context is None:
            self._tip_context = AgentCoreTIPContext(
                session_id=self.session_id,
                user_id=self.user_id,
                idp_token=self.idp_token,
                actor_context=self._actor_context,
            )
        return self._tip_context

    def get_credentials(self) -> AgentCoreCredentialSet:
        """Get credentials — called by AgentCore Runtime.

        Returns cached credentials if still valid (with 60s buffer).
        Performs TIP exchange if cache is stale or empty.
        """
        now = time.time()

        # Fast path: return cached creds if valid
        if self._last_creds and not self._last_creds.is_expired():
            # Refresh if getting close to expiry
            if now < (self._last_creds.expires_at - 120):
                return self._last_creds

        # Slow path: fetch fresh credentials via TIP
        tip_context = self._ensure_tip_context()
        creds = tip_context.get_session_credential_set()
        expires_at = float(tip_context.actor_context.get("duration_seconds", 3600))
        # Cache expiry is relative; actual expiry from SSO token
        actual_expires = now + expires_at - 300  # 5min safety buffer

        self._last_creds = AgentCoreCredentialSet(
            access_key=creds["AccessKeyId"],
            secret_key=creds["SecretAccessKey"],
            session_token=creds["SessionToken"],
            expires_at=actual_expires,
            user_id=self.user_id,
            session_id=self.session_id,
        )
        self._last_fetch = now

        logger.info(
            "AgentCore credential refresh for user=%s session=%s expires_in=%.0fs",
            self.user_id, self.session_id, actual_expires - now,
        )
        return self._last_creds

    def get_status(self) -> dict[str, Any]:
        """Return provider status for health checks."""
        creds = self._last_creds
        return {
            "provider": "agentcore-tip-mcp",
            "session_id": self.session_id,
            "user_id": self.user_id,
            "credentials_cached": creds is not None,
            "expires_at": creds.expires_at if creds else None,
            "expired": creds.is_expired() if creds else True,
            "last_fetch": self._last_fetch,
        }

    def get_session(self) -> boto3.Session:
        """Get a boto3 Session with current credentials."""
        creds = self.get_credentials()
        session = boto3.Session(
            aws_access_key_id=creds.access_key,
            aws_secret_access_key=creds.secret_key,
            aws_session_token=creds.session_token,
            region_name=self._actor_context.get("region") or "us-east-1",
        )
        # Tag with AgentCoreTIP/<call_path> so this session's AWS calls are
        # distinguishable in CloudTrail.userAgent, same as the MCP path.
        call_path = self._ensure_tip_context().call_path
        tag = f"AgentCoreTIP/{call_path}"
        if session._session.user_agent_extra:
            session._session.user_agent_extra += f" {tag}"
        else:
            session._session.user_agent_extra = tag
        return session


class AgentCoreAgentRuntime:
    """Managed AgentCore Runtime wrapper.

    Provides the entry point for Bedrock AgentCore to invoke AgentCore-TIP-MCP-Broker
    agents with proper credential management and MCP tool integration.

    When deployed to Bedrock AgentCore Runtime:
      1. AgentCore sends POST /invocations with user token in headers
      2. This runtime resolves credentials via AgentCoreCredentialProvider
      3. Agent logic executes with per-user TIP credentials
      4. Results are returned in AgentCore-compatible format

    MCP tools are exposed at /mcp/tools for discovery by the LLM orchestrator.
    """

    def __init__(self) -> None:
        self._providers: dict[tuple[str, str], AgentCoreCredentialProvider] = {}

    def resolve_provider(
        self,
        session_id: str,
        user_id: str,
        idp_token: Optional[str] = None,
    ) -> AgentCoreCredentialProvider:
        """Get or create a credential provider for a session."""
        key = (session_id, user_id)
        if key not in self._providers:
            self._providers[key] = AgentCoreCredentialProvider(
                session_id=session_id,
                user_id=user_id,
                idp_token=idp_token,
            )
        elif idp_token:
            # Update token if provided
            self._providers[key].idp_token = idp_token
        return self._providers[key]

    def invoke_agent(
        self,
        session_id: str,
        user_id: str,
        idp_token: Optional[str],
        agent_name: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Invoke an agent with proper credential management.

        This is the main entry point for AgentCore Runtime invocations.
        """
        provider = self.resolve_provider(session_id, user_id, idp_token)
        tip_context = provider._ensure_tip_context()

        # Import agent runners dynamically
        try:
            if agent_name == "ai_data_agent":
                from agents.ai_data_agent import run_ai_data_agent
                runner = run_ai_data_agent
            elif agent_name == "athena_lf_agent":
                from agents.athena_lf_agent import run_clients_query
                runner = run_clients_query
            else:
                return {
                    "ok": False,
                    "error": f"Unknown agent: {agent_name}",
                    "available_agents": ["ai_data_agent", "athena_lf_agent"],
                }
        except ImportError as exc:
            logger.error("Failed to load agent %s: %s", agent_name, exc)
            return {"ok": False, "error": f"Agent {agent_name} not available: {exc}"}

        try:
            result = runner(tip_context, payload)
            # Ensure AgentCore-compatible response
            result["session_id"] = session_id
            result["user_id"] = user_id
            result["agent"] = agent_name
            return result
        except Exception as exc:
            logger.exception("Agent %s failed for session %s", agent_name, session_id)
            return {
                "ok": False,
                "error": str(exc),
                "session_id": session_id,
                "agent": agent_name,
            }

    def get_status(self) -> dict[str, Any]:
        """Runtime status for health monitoring."""
        provider_statuses = {}
        for (session_id, user_id), provider in self._providers.items():
            provider_statuses[f"{session_id}:{user_id}"] = provider.get_status()

        return {
            "runtime": "agentcore_tip-agentcore",
            "version": "0.1.0",
            "active_sessions": len(self._providers),
            "providers": provider_statuses,
        }


# Module-level singleton for easy import
_runtime = AgentCoreAgentRuntime()


def get_runtime() -> AgentCoreAgentRuntime:
    """Get the global AgentCore runtime instance."""
    return _runtime


def invoke(
    session_id: str,
    user_id: str,
    idp_token: Optional[str] = None,
    agent_name: str = "ai_data_agent",
    payload: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Convenience function to invoke an agent via the managed runtime.

    Usage:
        result = invoke(
            session_id="sess-123",
            user_id="user-456",
            idp_token="<IDP_TOKEN>",
            agent_name="ai_data_agent",
            payload={"question": "top 5 customers by revenue"},
        )
    """
    return _runtime.invoke_agent(session_id, user_id, idp_token, agent_name, payload or {})
