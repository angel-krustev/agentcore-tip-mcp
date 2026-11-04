# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Session context management for user-scoped AWS data access."""

from __future__ import annotations

import contextvars
import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import boto3
import jwt

from ..core.credentials import AgentCoreTIPCredentialProvider
from ..core.exceptions import AuthenticationError
from ..core.hooks import BaseTelemetryHook, ConsoleTelemetryHook
from ..core.strategies.base import BaseExchangeStrategy
from ..core.strategies.sso_oidc import SsoOidcExchangeStrategy

_active_user_context: contextvars.ContextVar[Optional[dict[str, Any]]] = contextvars.ContextVar("active_user_context", default=None)
_session_cache: dict[tuple[str, str], dict[str, Any]] = {}
_session_lock = threading.Lock()
# Per-key loading guards: key → threading.Event
# When a thread starts exchanging, it places an Event here so other threads
# can wait for the result instead of all firing parallel network calls.
_loading_events: dict[tuple[str, str], threading.Event] = {}


def _extract_user_identity_from_jwt(token: str) -> str:
    if not token:
        return ""
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return ""
    for key in ("sub", "preferred_username", "email", "upn"):
        value = claims.get(key)
        if value:
            return str(value)
    return ""


@dataclass
class AgentCoreTIPContext:
    session_id: str = "default-session"
    user_id: Optional[str] = None
    idp_token: Optional[str] = None
    actor_context: dict[str, Any] = field(default_factory=dict)
    telemetry_hook: BaseTelemetryHook = field(default_factory=ConsoleTelemetryHook)
    exchange_strategy: Optional[BaseExchangeStrategy] = None
    credential_provider: Optional[AgentCoreTIPCredentialProvider] = None
    call_path: str = "agent"  # "agent", "mcp", "direct" — appears in CloudTrail userAgent
    _cache_key: Optional[tuple[str, str]] = None
    _last_access: float = 0.0

    def __post_init__(self) -> None:
        if not self.user_id and self.idp_token:
            self.user_id = _extract_user_identity_from_jwt(self.idp_token)
        if self.exchange_strategy is None:
            self.exchange_strategy = SsoOidcExchangeStrategy(
                client_id=self.actor_context.get("client_id", ""),
                role_arn=self.actor_context.get("role_arn", ""),
                region=self.actor_context.get("region"),
                intermediary_role_arn=self.actor_context.get("intermediary_role_arn"),
            )
        self.credential_provider = AgentCoreTIPCredentialProvider(session_factory=self.get_session_credential_set)
        self.telemetry_hook.on_session_start({"session_id": self.session_id, "user_id": self.user_id})

    def _token_hash(self, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def get_session_credential_set(self) -> dict[str, str]:
        if self.idp_token is None:
            raise AuthenticationError("No IDP token is available for this session.")
        # Key on the token hash too so two callers sharing a session_id / empty
        # user_id can never be served each other's cached credentials.
        cache_key = (
            self.session_id,
            f"{self.user_id or 'anonymous'}:{self._token_hash(self.idp_token)[:32]}",
        )

        while True:
            # 1. Fast path: read cache (lock only protects dict access)
            with _session_lock:
                cached = _session_cache.get(cache_key)
                if cached is not None:
                    expires_at = float(cached.get("expires_at", 0))
                    if time.time() < expires_at - 60:
                        return cached["credentials"]

                # 2. Check if another thread is already exchanging for this key
                event = _loading_events.get(cache_key)
                if event is not None:
                    _loading_events[cache_key] = event  # refresh ref
                else:
                    # We're the first — claim the slot
                    event = threading.Event()
                    _loading_events[cache_key] = event

            if event.is_set():
                # Another thread finished; retry the cache read at top of loop
                continue

            # 3. We're the exchange owner — do the slow network call OUTSIDE the lock
            should_cleanup = False
            try:
                credentials, expires_at = self.exchange_strategy.exchange(
                    self.idp_token, self.actor_context
                )
                should_cleanup = True
            except Exception:
                # On failure, clear the sentinel so the next call retries
                with _session_lock:
                    _loading_events.pop(cache_key, None)
                    # Return stale creds if available
                    stale = _session_cache.get(cache_key)
                if stale:
                    return stale["credentials"]
                raise

            # 4. Write result + signal waiters (lock only for dict mutation)
            with _session_lock:
                _session_cache[cache_key] = {"credentials": credentials, "expires_at": expires_at}
                _loading_events.pop(cache_key, None)
            event.set()

            self.telemetry_hook.on_token_exchange(
                {"session_id": self.session_id, "user_id": self.user_id, "expires_at": expires_at}
            )
            return credentials

    def session(self) -> boto3.Session:
        creds = self.get_session_credential_set()
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=self.actor_context.get("region") or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
        )

    def _tagged_session(self, call_path: str) -> boto3.Session:
        """Create a session with a user-agent extra tag for CloudTrail traceability.
        
        The tag appears in CloudTrail.userAgent as AgentCoreTIP/<call_path>, allowing you to
        distinguish MCP tool calls from agent invocations.
        """
        creds = self.get_session_credential_set()
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=self.actor_context.get("region") or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
        )
        # boto3.Session has no `config` kwarg (that's a client-level concept), so
        # append the tag directly onto the underlying botocore session instead of
        # overwriting it, which would wipe out boto3's own "Botocore/<ver>" marker.
        tag = f"AgentCoreTIP/{call_path}"
        if session._session.user_agent_extra:
            session._session.user_agent_extra += f" {tag}"
        else:
            session._session.user_agent_extra = tag
        return session

    def session_for_call_path(self) -> boto3.Session:
        """Return a session tagged with this context's call_path."""
        return self._tagged_session(self.call_path)

    def lakeformation_session(self) -> boto3.Session:
        return self.session_for_call_path()

    def scoped_s3_client(self, uri: str):
        from ..integrations.s3_access_grants import S3AccessGrantsClientResolver

        resolver = S3AccessGrantsClientResolver(self)
        return resolver.resolve(uri)


def set_active_user_context(context: dict[str, Any]) -> None:
    _active_user_context.set(context)


def get_active_user_session() -> Optional[AgentCoreTIPContext]:
    context = _active_user_context.get()
    if context is None:
        return None
    return context.get("session")


class user_session:
    """Context manager used to bind a user-scoped session to the current execution context."""

    def __init__(self, idp_token: str, session_id: str = "default-session", **kwargs):
        self.idp_token = idp_token
        self.session_id = session_id
        self.kwargs = kwargs
        self._token = None
        self._context = None

    def __enter__(self):
        self._context = AgentCoreTIPContext(session_id=self.session_id, idp_token=self.idp_token, actor_context=self.kwargs)
        set_active_user_context({"session": self._context})
        return self._context

    def __exit__(self, exc_type, exc_val, exc_tb):
        set_active_user_context(None)
        return False


def get_lakeformation_session() -> boto3.Session:
    ctx = get_active_user_session()
    if ctx is None:
        raise AuthenticationError("No active AgentCoreTIP user session is bound.")
    return ctx.lakeformation_session()


def get_scoped_s3_client(uri: str):
    ctx = get_active_user_session()
    if ctx is None:
        raise AuthenticationError("No active AgentCoreTIP user session is bound.")
    return ctx.scoped_s3_client(uri)
