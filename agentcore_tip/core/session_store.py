# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Ephemeral session store: opaque ``session_ref`` -> Identity Center context.

Plane A writes a session after the one-time token exchange; Plane B resolves
it per tool call. Only the Identity Center context assertion and the user id
are stored -- never IDP bearer tokens, refresh tokens or AWS credentials.

In Redis every session record is Fernet-encrypted (``PEP_ENCRYPTION_KEY``): the
Identity Center context is a credential-equivalent assertion, so anyone who can
read Redis must not be able to read it. The record also carries its own
``session_ref`` inside the ciphertext, so a record copied under another key is
rejected. The in-memory fallback (no ``REDIS_URL``) is for local development.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import threading
import time
from typing import Any, Optional
from urllib.parse import parse_qs, urlsplit

from cryptography.fernet import Fernet, MultiFernet

from .config import pep_config

logger = logging.getLogger(__name__)

_REDIS_PREFIX = "vt:session:"
_BIND_PREFIX = "vt:bind:"
_SESSION_REF_RE = re.compile(r"^sess_[0-9a-f]{32}$")
_KEY_HELP = (
    "PEP_ENCRYPTION_KEY must be a Fernet key (32 url-safe base64 bytes). Generate one with: "
    'python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
)
# redis-py URL options that would silently turn TLS verification off.
_UNVERIFIED_CERT_REQS = {"none", "optional", "cert_none", "cert_optional"}
_FALSE_VALUES = {"false", "0", "no", "off"}


class SessionStoreConfigError(RuntimeError):
    pass


def validate_redis_url(url: str) -> None:
    """Require a TLS Redis URL (``rediss://``) with certificate and hostname verification on.

    Fails closed: plaintext ``redis://``, ``unix://`` and any other scheme are refused, as are
    URL options that disable verification. Messages never contain the URL (it may hold the password).
    """
    if not isinstance(url, str) or url[:9].lower() != "rediss://":
        raise SessionStoreConfigError(
            "REDIS_URL must start with rediss:// (TLS). Plaintext redis:// and other schemes are not allowed."
        )
    try:
        parts = urlsplit(url)
        host = parts.hostname
        options = {name.lower(): [v.lower() for v in values] for name, values in parse_qs(parts.query).items()}
    except ValueError:
        raise SessionStoreConfigError("REDIS_URL is malformed.") from None
    if not host:
        raise SessionStoreConfigError("REDIS_URL must include a host.")
    if any(value in _UNVERIFIED_CERT_REQS for value in options.get("ssl_cert_reqs", [])):
        raise SessionStoreConfigError("REDIS_URL must not disable TLS certificate verification (ssl_cert_reqs).")
    if any(value in _FALSE_VALUES for value in options.get("ssl_check_hostname", [])):
        raise SessionStoreConfigError("REDIS_URL must not disable TLS hostname verification (ssl_check_hostname).")


def is_valid_session_ref(session_ref: str) -> bool:
    return bool(session_ref) and _SESSION_REF_RE.match(session_ref) is not None


def build_cipher(raw_keys: Optional[str]) -> MultiFernet:
    """Build the record cipher from ``PEP_ENCRYPTION_KEY`` (comma-separated for rotation).

    The first key encrypts; all keys decrypt, so a new key can be put in front without
    invalidating live sessions. Error messages never contain key material.
    """
    keys = [part.strip() for part in (raw_keys or "").split(",") if part.strip()]
    if not keys:
        raise SessionStoreConfigError("PEP_ENCRYPTION_KEY is required when REDIS_URL is set. " + _KEY_HELP)
    try:
        return MultiFernet([Fernet(key.encode("ascii")) for key in keys])
    except ValueError:
        raise SessionStoreConfigError("PEP_ENCRYPTION_KEY is not a valid Fernet key. " + _KEY_HELP) from None


class SessionStore:
    """Redis-backed store (encrypted at the application layer) with an in-memory dev fallback."""

    def __init__(self) -> None:
        self._redis: Any = None
        self._cipher: Optional[MultiFernet] = None
        self._mem_store: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = threading.Lock()

    async def init(self) -> None:
        if self._redis is not None:
            return
        if not pep_config.redis_url:
            logger.warning("REDIS_URL not set: sessions are kept in process memory (per-replica, lost on restart).")
            return
        # Validate transport and key before connecting: fail closed, never fall back to plaintext.
        validate_redis_url(pep_config.redis_url)
        self._cipher = build_cipher(pep_config.encryption_key)
        import redis.asyncio as redis

        self._redis = redis.from_url(pep_config.redis_url, decode_responses=True)

    async def close(self) -> None:
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None

    def _seal(self, payload: dict[str, Any]) -> str:
        if self._cipher is None:
            raise SessionStoreConfigError("Redis session storage requires PEP_ENCRYPTION_KEY.")
        return self._cipher.encrypt(json.dumps(payload).encode("utf-8")).decode("ascii")

    def _open(self, stored: str, session_ref: str) -> Optional[dict[str, Any]]:
        if self._cipher is None:
            raise SessionStoreConfigError("Redis session storage requires PEP_ENCRYPTION_KEY.")
        try:
            payload = json.loads(self._cipher.decrypt(stored.encode("ascii")).decode("utf-8"))
        except Exception:
            # Tampered, truncated, wrong-key or legacy plaintext record: treat as no session.
            logger.warning("Rejected an unreadable session record")
            return None
        # The record must belong to the ref it was fetched under.
        if not isinstance(payload, dict) or payload.get("ref") != session_ref:
            logger.warning("Rejected a session record bound to a different session_ref")
            return None
        return payload

    async def create_session(
        self,
        idc_context: str,
        user_id: str,
        ttl: Optional[int] = None,
    ) -> str:
        if not idc_context:
            raise ValueError("idc_context is required")
        if not user_id:
            raise ValueError("user_id is required")
        ttl_seconds = int(ttl or pep_config.session_ttl_seconds)
        session_ref = f"sess_{secrets.token_hex(16)}"
        now = time.time()
        payload: dict[str, Any] = {
            "ref": session_ref,
            "idc_context": idc_context,
            "user_id": user_id,
            "created_at": now,
            "expires_at": now + ttl_seconds,
        }
        if self._redis is not None:
            await self._redis.set(_REDIS_PREFIX + session_ref, self._seal(payload), ex=ttl_seconds)
        else:
            with self._lock:
                self._purge_expired(now)
                self._mem_store[session_ref] = (now + ttl_seconds, payload)
        return session_ref

    async def get_session(self, session_ref: str) -> Optional[dict[str, Any]]:
        # Reject malformed refs before they can reach a Redis key.
        if not is_valid_session_ref(session_ref):
            return None
        if self._redis is not None:
            stored = await self._redis.get(_REDIS_PREFIX + session_ref)
            return self._open(stored, session_ref) if stored else None
        with self._lock:
            entry = self._mem_store.get(session_ref)
            if entry is None:
                return None
            expires_at, payload = entry
            if time.time() > expires_at:
                del self._mem_store[session_ref]
                return None
            return dict(payload)

    async def bind_agent(self, session_ref: str, agent_identity: str, expires_at: float) -> bool:
        """Trust-on-first-use: pin the session to ``agent_identity``.

        The first caller to present a valid ``session_ref`` becomes its owner; every
        later call must present the same identity. Atomic across replicas (Redis
        SET NX). Returns True when ``agent_identity`` owns the session. The bound value
        is a role ARN, not a secret, so it is stored unencrypted.
        """
        if not is_valid_session_ref(session_ref) or not agent_identity:
            return False
        if self._redis is not None:
            key = _BIND_PREFIX + session_ref
            remaining = max(1, int(expires_at - time.time()))
            if await self._redis.set(key, agent_identity, nx=True, ex=remaining):
                return True
            return (await self._redis.get(key)) == agent_identity
        with self._lock:
            entry = self._mem_store.get(session_ref)
            if entry is None or time.time() > entry[0]:
                return False
            return entry[1].setdefault("bound_agent", agent_identity) == agent_identity

    async def delete_session(self, session_ref: str) -> None:
        if not is_valid_session_ref(session_ref):
            return
        if self._redis is not None:
            await self._redis.delete(_REDIS_PREFIX + session_ref, _BIND_PREFIX + session_ref)
            return
        with self._lock:
            self._mem_store.pop(session_ref, None)

    def _purge_expired(self, now: float) -> None:
        expired = [ref for ref, (expires_at, _) in self._mem_store.items() if now > expires_at]
        for ref in expired:
            del self._mem_store[ref]


session_store = SessionStore()
